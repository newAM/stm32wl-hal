#![no_std]
#![no_main]

use core::fmt::Write;
use defmt::unwrap;
use defmt_rtt as _; // global logger
use panic_probe as _;
use stm32wl_hal::{
    dma::{AllDma, Dma1Ch3, Dma2Ch6},
    embedded_hal::prelude::*,
    gpio::{pins, PortA, PortC},
    pac, rcc,
    uart::{self, LpUart, Uart1},
};

#[defmt_test::tests]
mod tests {
    use super::*;

    struct TestArgs {
        lpuart: LpUart<(pins::C0, Dma2Ch6), pins::C1>,
        uart1: Uart1<pins::A10, (pins::A9, Dma1Ch3)>,
    }

    #[init]
    fn init() -> TestArgs {
        let mut dp: pac::Peripherals = unwrap!(pac::Peripherals::take());
        rcc::set_sysclk_to_msi_48megahertz(&mut dp.FLASH, &mut dp.PWR, &mut dp.RCC);

        dp.RCC.cr.modify(|_, w| w.hsion().set_bit());
        while dp.RCC.cr.read().hsirdy().is_not_ready() {}

        let dma: AllDma = AllDma::split(dp.DMAMUX, dp.DMA1, dp.DMA2, &mut dp.RCC);
        let gpioa: PortA = PortA::split(dp.GPIOA, &mut dp.RCC);
        let gpioc: PortC = PortC::split(dp.GPIOC, &mut dp.RCC);

        let lpuart: LpUart<(pins::C0, Dma2Ch6), pins::C1> =
            LpUart::new(dp.LPUART, 115200, uart::Clk::Hsi16, &mut dp.RCC)
                .enable_rx_dma(gpioc.pc0, dma.d2c6)
                .enable_tx(gpioc.pc1);
        let uart1: Uart1<pins::A10, (pins::A9, Dma1Ch3)> =
            Uart1::new(dp.USART1, 115200, uart::Clk::Hsi16, &mut dp.RCC)
                .enable_rx(gpioa.pa10)
                .enable_tx_dma(gpioa.pa9, dma.d1c3);

        defmt::warn!(
            "UART tests require PC1 (LPUART TX) connected to PA10 (UART1 RX) and \
             PC0 (LPUART RX) connected to PA9 (UART1 TX)"
        );

        TestArgs { lpuart, uart1 }
    }

    #[test]
    fn single_byte_loopback_no_dma(ta: &mut TestArgs) {
        const WORD: u8 = 0xAA;
        unwrap!(nb::block!(ta.lpuart.write(WORD)));
        let out: u8 = unwrap!(nb::block!(ta.uart1.read()));

        defmt::assert_eq!(WORD, out);
    }

    #[test]
    fn single_byte_loopback_with_dma(ta: &mut TestArgs) {
        const WORD: u8 = 0x55;
        unwrap!(ta.uart1.bwrite_all(&[WORD]));
        let mut read_buf: [u8; 1] = [0];
        unwrap!(ta.lpuart.bread_all(&mut read_buf));

        defmt::assert_eq!(WORD, read_buf[0]);
    }

    #[test]
    fn core_fmt(ta: &mut TestArgs) {
        const EXPECTED: &str = "Hello, world!\n";
        unwrap!(write!(&mut ta.lpuart, "Hello, {}!\n", "world").ok());
        for &expected_byte in EXPECTED.as_bytes() {
            let rx_byte: u8 = unwrap!(nb::block!(ta.uart1.read()));
            defmt::assert_eq!(rx_byte, expected_byte);
        }
    }
}
