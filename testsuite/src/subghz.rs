#![no_std]
#![no_main]

use defmt::unwrap;
use defmt_rtt as _; // global logger
use panic_probe as _;

use nucleo_wl55jc_bsp as bsp;
use static_assertions as sa;

use bsp::{
    hal::{
        cortex_m::{self, delay::Delay},
        dma::{AllDma, Dma1Ch1, Dma2Ch1},
        gpio::{PortA, PortC, RfNssDbg, SgMisoDbg, SgMosiDbg, SgSckDbg},
        pac::{self, DWT},
        rcc,
        rng::{self, Rng},
        spi::{SgMiso, SgMosi},
        subghz::{
            rfbusys, wakeup, AddrComp, CalibrateImage, CfgIrq, CmdStatus, CodingRate, CrcType,
            FallbackMode, FskBandwidth, FskBitrate, FskFdev, FskModParams, FskPulseShape,
            GenericPacketParams, HeaderType, Irq, LoRaBandwidth, LoRaModParams, LoRaPacketParams,
            LoRaSyncWord, Ocp, PaConfig, PacketType, PktCtrl, PreambleDetection, RampTime, RegMode,
            RfFreq, SleepCfg, SpreadingFactor, StandbyClk, Startup, Status, StatusMode, SubGhz,
            TcxoMode, TcxoTrim, Timeout, TxParams,
        },
        util::new_delay,
    },
    RfSwitch,
};

type MySubghz = SubGhz<Dma1Ch1, Dma2Ch1>;

const FREQ: u32 = 48_000_000;
const CYC_PER_US: u32 = FREQ / 1000 / 1000;
const CYC_PER_MS: u32 = FREQ / 1000;
const CYC_PER_SEC: u32 = FREQ;

use core::time::Duration;

const PING_DATA: &str = "PING";
const PONG_DATA: &str = "PONG";
const DATA_LEN: u8 = PING_DATA.len() as u8;
sa::const_assert_eq!(PING_DATA.len(), PONG_DATA.len());
const PING_DATA_BYTES: &[u8] = PING_DATA.as_bytes();
const PONG_DATA_BYTES: &[u8] = PONG_DATA.as_bytes();
const PREAMBLE_LEN: u16 = 5 * 8;

const RF_FREQ: RfFreq = RfFreq::from_frequency(434_000_000);

const SYNC_WORD: [u8; 8] = [0x79, 0x80, 0x0C, 0xC0, 0x29, 0x95, 0xF8, 0x4A];
const SYNC_WORD_LEN: u8 = SYNC_WORD.len() as u8;
const SYNC_WORD_LEN_BITS: u8 = SYNC_WORD_LEN * 8;

const TX_BUF_OFFSET: u8 = 128;
const RX_BUF_OFFSET: u8 = 0;

const FSK_PACKET_PARAMS: GenericPacketParams = GenericPacketParams::new()
    .set_preamble_len(PREAMBLE_LEN)
    .set_preamble_detection(PreambleDetection::Bit8)
    .set_sync_word_len(SYNC_WORD_LEN_BITS)
    .set_addr_comp(AddrComp::Node)
    .set_header_type(HeaderType::Fixed)
    .set_payload_len(DATA_LEN)
    .set_crc_type(CrcType::Byte2)
    .set_whitening_enable(true);

const LORA_PACKET_PARAMS: LoRaPacketParams = LoRaPacketParams::new()
    .set_crc_en(true)
    .set_preamble_len(PREAMBLE_LEN)
    .set_payload_len(DATA_LEN)
    .set_invert_iq(false)
    .set_header_type(HeaderType::Fixed);

const FSK_MOD_PARAMS: FskModParams = FskModParams::new()
    .set_bitrate(FskBitrate::from_bps(20_000))
    .set_pulse_shape(FskPulseShape::None)
    .set_bandwidth(FskBandwidth::Bw58)
    .set_fdev(FskFdev::from_hertz(10_000));

sa::const_assert!(FSK_MOD_PARAMS.is_valid_worst_case());

const LORA_MOD_PARAMS: LoRaModParams = LoRaModParams::new()
    .set_bw(LoRaBandwidth::Bw125)
    .set_cr(CodingRate::Cr45)
    .set_ldro_en(true)
    .set_sf(SpreadingFactor::Sf7);

const PA_CONFIG: PaConfig = PaConfig::LP_10;
const TX_PARAMS: TxParams = TxParams::LP_10.set_ramp_time(RampTime::Micros40);

const TCXO_MODE: TcxoMode = TcxoMode::new()
    .set_tcxo_trim(TcxoTrim::Volts1pt7)
    .set_timeout(Timeout::from_duration_sat(Duration::from_millis(10)));

// WARNING will wrap-around eventually, use this for relative timing only
defmt::timestamp!("{=u32:us}", DWT::cycle_count() / CYC_PER_US);

fn tx_or_panic(sg: &mut MySubghz, rfs: &mut RfSwitch) {
    rfs.set_tx_lp();
    unwrap!(sg.set_tx(Timeout::DISABLED));
    let start_cc: u32 = DWT::cycle_count();
    loop {
        let (status, irq_status): (Status, u16) = unwrap!(sg.irq_status());
        if irq_status & Irq::TxDone.mask() != 0 {
            rfs.set_rx();
            unwrap!(sg.clear_irq_status(irq_status));
            defmt::info!("TX done");
            break;
        }

        let elapsed_s: u32 = DWT::cycle_count().wrapping_sub(start_cc) / CYC_PER_SEC;
        defmt::assert!(
            elapsed_s < 1,
            "Timeout waiting for TX completion status={}",
            status
        );
    }
}

/// This test should be run simultaneously on two boards.
///
/// Both radios transmit `b"PING"`.
///
/// The first radio to receive `b"PING"` transmits `b"PONG"` in reply.
fn ping_pong(sg: &mut MySubghz, rng: &mut Rng, rfs: &mut RfSwitch, pkt: PacketType) {
    unwrap!(sg.set_standby(StandbyClk::Rc));
    let status: Status = unwrap!(sg.status());
    defmt::assert_ne!(status.cmd(), Ok(CmdStatus::ExecutionFailure));
    defmt::assert_eq!(status.mode(), Ok(StatusMode::StandbyRc));

    unwrap!(sg.set_tcxo_mode(&TCXO_MODE));
    unwrap!(sg.set_standby(StandbyClk::Hse));
    let status: Status = unwrap!(sg.status());
    defmt::assert_ne!(status.cmd(), Ok(CmdStatus::ExecutionFailure));
    defmt::assert_eq!(status.mode(), Ok(StatusMode::StandbyHse));
    unwrap!(sg.set_tx_rx_fallback_mode(FallbackMode::StandbyHse));

    unwrap!(sg.set_regulator_mode(RegMode::Ldo));
    unwrap!(sg.set_buffer_base_address(TX_BUF_OFFSET, RX_BUF_OFFSET));
    unwrap!(sg.set_pa_config(&PA_CONFIG));
    unwrap!(sg.set_pa_ocp(Ocp::Max60m));
    unwrap!(sg.set_tx_params(&TX_PARAMS));

    let status: Status = unwrap!(sg.status());
    defmt::assert_eq!(status.mode(), Ok(StatusMode::StandbyHse));

    unwrap!(sg.set_packet_type(pkt));
    match pkt {
        PacketType::Fsk => {
            unwrap!(sg.set_sync_word(&SYNC_WORD));
            unwrap!(sg.set_fsk_mod_params(&FSK_MOD_PARAMS));
            unwrap!(sg.set_packet_params(&FSK_PACKET_PARAMS));
        }
        PacketType::LoRa => {
            unwrap!(sg.set_lora_sync_word(LoRaSyncWord::Public));
            unwrap!(sg.set_lora_mod_params(&LORA_MOD_PARAMS));
            unwrap!(sg.set_lora_packet_params(&LORA_PACKET_PARAMS));
        }
        PacketType::Bpsk => defmt::todo!(),
        PacketType::Msk => defmt::todo!(),
    }

    unwrap!(sg.calibrate_image(CalibrateImage::ISM_430_440));
    unwrap!(sg.set_rf_frequency(&RF_FREQ));

    unwrap!(sg.write_buffer(TX_BUF_OFFSET, PING_DATA_BYTES));

    const IRQ_CFG: CfgIrq = CfgIrq::new()
        .irq_enable_all(Irq::RxDone)
        .irq_enable_all(Irq::Timeout);
    unwrap!(sg.set_irq_cfg(&IRQ_CFG));

    const MAX_ATTEMPTS: u32 = 100;
    let mut attempt: u32 = 0;
    loop {
        defmt::info!("Attempt: {}/{}", attempt, MAX_ATTEMPTS);

        // 45 - 300 ms
        let (rx_timeout, rx_timeout_ms): (Timeout, i32) = {
            let rand_u8: u8 = unwrap!(rng.try_u8());
            let millis: u32 = u32::from(rand_u8).saturating_add(45);
            (Timeout::from_millis_sat(millis), millis as i32)
        };

        defmt::debug!("RX with timeout {:?} ms", rx_timeout_ms);
        unwrap!(sg.set_rx(rx_timeout));

        let start_cc: u32 = DWT::cycle_count();
        loop {
            let (status, irq_status) = unwrap!(sg.irq_status());

            let elapsed_ms: u32 = DWT::cycle_count().wrapping_sub(start_cc) / CYC_PER_MS;

            if irq_status & Irq::Timeout.mask() != 0 {
                let elapsed_ms: i32 = elapsed_ms as i32;
                defmt::info!(
                    "RX timeout {} ms Δ {} ms",
                    elapsed_ms,
                    (rx_timeout_ms - elapsed_ms).abs()
                );
                defmt::assert_eq!(status.mode(), Ok(StatusMode::StandbyRc));
                unwrap!(sg.set_standby(StandbyClk::Hse));
                unwrap!(sg.clear_irq_status(irq_status));

                tx_or_panic(sg, rfs);
                break;
            } else if irq_status & Irq::RxDone.mask() != 0 {
                defmt::info!("RX done");
                defmt::assert_eq!(status.mode(), Ok(StatusMode::StandbyHse));
                unwrap!(sg.clear_irq_status(irq_status));

                match pkt {
                    PacketType::Fsk => defmt::info!("{}", sg.fsk_packet_status()),
                    PacketType::LoRa => defmt::info!("{}", sg.lora_packet_status()),
                    PacketType::Bpsk => defmt::todo!(),
                    PacketType::Msk => defmt::todo!(),
                }

                let (status, len, ptr) = unwrap!(sg.rx_buffer_status());
                defmt::assert_eq!(len, DATA_LEN);
                defmt::assert_eq!(status.cmd(), Ok(CmdStatus::Available));
                defmt::assert_eq!(ptr, RX_BUF_OFFSET);
                defmt::assert_eq!(irq_status, 0b10);
                let mut data_buf: [u8; DATA_LEN as usize] = [0; DATA_LEN as usize];
                unwrap!(sg.read_buffer(ptr, &mut data_buf));
                match data_buf.as_ref() {
                    PING_DATA_BYTES => {
                        defmt::info!("received PING");

                        // respond with pong
                        unwrap!(sg.write_buffer(TX_BUF_OFFSET, PONG_DATA_BYTES));

                        // assume the other radio will get it in 10 transmissions
                        for _ in 0..10 {
                            tx_or_panic(sg, rfs);
                        }
                    }
                    PONG_DATA_BYTES => {
                        defmt::info!("received PONG");
                    }
                    _ => defmt::panic!(
                        "Unknown data: {:?} PING={:?} PONG={:?}",
                        data_buf,
                        PING_DATA_BYTES,
                        PONG_DATA_BYTES
                    ),
                }

                rfs.set_rx();
                return;
            } else {
                defmt::assert_eq!(irq_status, 0);
                defmt::assert_ne!(status.cmd(), Ok(CmdStatus::Available));
                defmt::assert_ne!(status.cmd(), Ok(CmdStatus::ProcessingError));
                defmt::assert_ne!(status.cmd(), Ok(CmdStatus::ExecutionFailure));

                defmt::assert!(
                    elapsed_ms < 1_000,
                    "Timeout waiting for RX completion status={}",
                    status
                );
            }
        }

        attempt = attempt.saturating_add(1);
        defmt::assert!(attempt < MAX_ATTEMPTS);
    }
}

#[defmt_test::tests]
mod tests {
    use super::*;

    // unsafe, but keeps the stack happy
    static mut BUF: [u8; 255] = [0; 255];

    struct TestArgs {
        sg: MySubghz,
        rng: Rng,
        delay: Delay,
        rfs: RfSwitch,
    }

    #[init]
    fn init() -> TestArgs {
        cortex_m::interrupt::free(|cs| {
            let mut cp: pac::CorePeripherals = unwrap!(pac::CorePeripherals::take());
            let mut dp: pac::Peripherals = unwrap!(pac::Peripherals::take());

            unsafe { rcc::set_sysclk_msi_max(&mut dp.FLASH, &mut dp.PWR, &mut dp.RCC, cs) };
            defmt::assert_eq!(rcc::sysclk_hz(&dp.RCC), FREQ);

            let gpioa: PortA = PortA::split(dp.GPIOA, &mut dp.RCC);
            let gpioc: PortC = PortC::split(dp.GPIOC, &mut dp.RCC);
            let mut rfs: RfSwitch = RfSwitch::new(gpioc.c3, gpioc.c4, gpioc.c5, cs);
            rfs.set_rx();

            let dma = AllDma::split(dp.DMAMUX, dp.DMA1, dp.DMA2, &mut dp.RCC);

            let rng: Rng = Rng::new(dp.RNG, rng::Clk::Msi, &mut dp.RCC);
            let delay: Delay = new_delay(cp.SYST, &dp.RCC);

            let sg: MySubghz = MySubghz::new_with_dma(dp.SPI3, dma.d1.c1, dma.d2.c1, &mut dp.RCC);
            let _: RfNssDbg = RfNssDbg::new(gpioa.a4, cs);
            let _: SgSckDbg = SgSckDbg::new(gpioa.a5, cs);
            let _: SgMisoDbg = SgMisoDbg::new(gpioa.a6, cs);
            let _: SgMosiDbg = SgMosiDbg::new(gpioa.a7, cs);

            cp.DCB.enable_trace();
            cp.DWT.enable_cycle_counter();
            cp.DWT.set_cycle_count(0);

            TestArgs {
                sg,
                rng,
                delay,
                rfs,
            }
        })
    }

    #[test]
    fn buffer_io(ta: &mut TestArgs) {
        const DATA: [u8; 255] = [0x5A; 255];
        while rfbusys() {}
        let start: u32 = DWT::cycle_count();
        unwrap!(ta.sg.write_buffer(0, &DATA));
        unwrap!(ta
            .sg
            .read_buffer(0, unsafe { unwrap!(core::ptr::addr_of_mut!(BUF).as_mut()) }));
        let end: u32 = DWT::cycle_count();
        defmt::info!("Cycles 255B: {}", end - start);
        defmt::assert_eq!(DATA, unsafe { BUF });

        let mut buf: [u8; 0] = [];
        while rfbusys() {}
        let start: u32 = DWT::cycle_count();
        unwrap!(ta.sg.write_buffer(0, &buf));
        unwrap!(ta.sg.read_buffer(0, &mut buf));
        let end: u32 = DWT::cycle_count();
        defmt::info!("Cycles 0B: {}", end - start);
    }

    #[test]
    fn buffer_io_no_dma(_: &mut TestArgs) {
        let mut sg: SubGhz<SgMiso, SgMosi> = unsafe { SubGhz::<SgMiso, SgMosi>::steal() };

        const DATA: [u8; 255] = [0x45; 255];
        while rfbusys() {}
        let start: u32 = DWT::cycle_count();
        unwrap!(sg.write_buffer(0, &DATA));
        unwrap!(sg.read_buffer(0, unsafe { unwrap!(core::ptr::addr_of_mut!(BUF).as_mut()) }));
        let end: u32 = DWT::cycle_count();
        defmt::info!("Cycles 255B: {}", end - start);
        defmt::assert_eq!(DATA, unsafe { BUF });

        let mut buf: [u8; 0] = [];
        while rfbusys() {}
        let start: u32 = DWT::cycle_count();
        unwrap!(sg.write_buffer(0, &buf));
        unwrap!(sg.read_buffer(0, &mut buf));
        let end: u32 = DWT::cycle_count();
        defmt::info!("Cycles 0B: {}", end - start);
    }

    #[test]
    fn sleep_enter_exit(ta: &mut TestArgs) {
        const SLEEP_CFG: SleepCfg = SleepCfg::new()
            .set_rtc_wakeup_en(false)
            .set_startup(Startup::Cold);

        unwrap!(unsafe { ta.sg.set_sleep(SLEEP_CFG) });
        ta.delay.delay_us(500);

        let start: u32 = DWT::cycle_count();
        unsafe { wakeup() }
        let end: u32 = DWT::cycle_count();
        defmt::info!("{} cycles to wake radio", end - start);

        let status: Status = unwrap!(ta.sg.status());
        defmt::assert_eq!(status.mode(), Ok(StatusMode::StandbyRc));
    }

    #[test]
    fn read_write_register(ta: &mut TestArgs) {
        let original_value = unwrap!(ta.sg.init_whitening());
        let test_value = !original_value;
        unwrap!(ta.sg.set_init_whitening(test_value));
        let new_value = unwrap!(ta.sg.init_whitening());
        defmt::assert_eq!(test_value, new_value);

        unwrap!(ta.sg.set_init_whitening(original_value));
    }

    #[test]
    fn set_whitening_seed_operations(ta: &mut TestArgs) {
        let original_raw_pkt_ctrl = (unwrap!(ta.sg.pkt_ctrl())).as_bits();
        let original_init_whitening = unwrap!(ta.sg.init_whitening());
        let original_whitening_seed: u16 =
            (((original_raw_pkt_ctrl & 0x01) as u16) << 8) | original_init_whitening as u16;
        let test_value = !original_whitening_seed & 0x01FF;
        let expected_raw_pkt_ctrl =
            (original_raw_pkt_ctrl & 0xFE) | ((test_value >> 8) & 0x01) as u8;
        let expected_init_whitening = (test_value & 0x00FF) as u8;

        unwrap!(ta.sg.set_whitening_seed(test_value));

        defmt::assert_eq!(expected_raw_pkt_ctrl, (unwrap!(ta.sg.pkt_ctrl())).as_bits());
        defmt::assert_eq!(expected_init_whitening, unwrap!(ta.sg.init_whitening()));

        unwrap!(ta.sg.set_init_whitening(original_init_whitening));
        unwrap!(ta.sg.set_pkt_ctrl(PktCtrl::from_raw(original_raw_pkt_ctrl)));
    }

    #[test]
    fn fsk_ping_pong(ta: &mut TestArgs) {
        let sg: &mut MySubghz = &mut ta.sg;
        let rng: &mut Rng = &mut ta.rng;
        let rfs: &mut RfSwitch = &mut ta.rfs;

        ping_pong(sg, rng, rfs, PacketType::Fsk);
    }

    #[test]
    fn lora_ping_pong(ta: &mut TestArgs) {
        let sg: &mut MySubghz = &mut ta.sg;
        let rng: &mut Rng = &mut ta.rng;
        let rfs: &mut RfSwitch = &mut ta.rfs;

        ping_pong(sg, rng, rfs, PacketType::LoRa);
    }
}
