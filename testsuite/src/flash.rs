#![no_std]
#![no_main]

use core::{mem::size_of, ptr::read_volatile};
use defmt::unwrap;
use defmt_rtt as _; // global logger
use nucleo_wl55jc_bsp::hal::{
    cortex_m,
    flash::{self, Flash, Page},
    pac::{self, DWT},
    rcc,
    rng::{self, Rng},
};
use panic_probe as _;
use rand::Rng as RngTrait;
use static_assertions as sa;

const FREQ: u32 = 48_000_000;
const CYC_PER_MICRO: u32 = FREQ / 1000 / 1000;

// WARNING will wrap-around eventually, use this for relative timing only
defmt::timestamp!("{=u32:us}", DWT::cycle_count() / CYC_PER_MICRO);

#[cortex_m_rt::exception]
#[allow(non_snake_case)]
unsafe fn HardFault(ef: &cortex_m_rt::ExceptionFrame) -> ! {
    cortex_m::interrupt::disable();
    defmt::error!("HardFault {:#}", defmt::Debug2Format(ef));
    defmt::flush();
    loop {
        cortex_m::asm::udf()
    }
}

#[defmt_test::tests]
mod tests {
    use super::*;

    struct TestArgs {
        flash: pac::FLASH,
        page: Page,
        // address to use for testing
        // incremented by the test after the address is programmed
        addr: usize,
        rng: Rng,
    }

    #[init]
    fn init() -> TestArgs {
        let mut cp: pac::CorePeripherals = unwrap!(pac::CorePeripherals::take());
        let mut dp: pac::Peripherals = unwrap!(pac::Peripherals::take());

        cortex_m::interrupt::free(|cs| unsafe {
            rcc::set_sysclk_msi_max(&mut dp.FLASH, &mut dp.PWR, &mut dp.RCC, cs)
        });

        cp.DCB.enable_trace();
        cp.DWT.enable_cycle_counter();
        cp.DWT.set_cycle_count(0);

        let mut rng: Rng = Rng::new(dp.RNG, rng::Clk::MSI, &mut dp.RCC);

        // flash only gets 20k program cycles
        // change the location each time to prevent wearout of CI boards
        let page: u8 = rng.gen_range(64..127);
        let page: Page = unwrap!(Page::from_index(page));

        defmt::info!(
            "Testing with page {}, {:#08X}",
            page.clone().to_index(),
            page.addr()
        );

        TestArgs {
            flash: dp.FLASH,
            page,
            addr: page.addr(),
            rng,
        }
    }

    #[test]
    fn start_end_addrs() {
        defmt::debug!("FLASH_START={:#08X}", flash::FLASH_START);
        defmt::debug!("flash_end()={:#08X}", flash::flash_end());
        defmt::assert_eq!(flash::FLASH_START, 0x0800_0000);
        defmt::assert_eq!(flash::flash_end(), 0x0803_FFFF);
        defmt::assert_eq!(flash::num_pages(), 0x80);

        // ensure previous logs are seen before we start executing code that can
        // result in difficult-to-debug situations
        defmt::flush();
    }

    #[test]
    fn page_erase(ta: &mut TestArgs) {
        defmt::debug!("data at page start before erase: {:#08X}", unsafe {
            read_volatile(ta.page.addr() as *const u64)
        });

        let mut flash: Flash = Flash::unlock(&mut ta.flash);

        let start: u32 = DWT::cycle_count();
        unwrap!(unsafe { flash.page_erase(ta.page.clone()) });
        let end: u32 = DWT::cycle_count();
        let elapsed: u32 = end.wrapping_sub(start);

        defmt::info!(
            "2048B page erase duration: {=u32:us} seconds",
            elapsed / CYC_PER_MICRO
        );

        defmt::assert_eq!(
            unsafe { read_volatile(ta.page.addr() as *const u64) },
            u64::MAX
        );
    }

    #[test]
    fn fast_program(ta: &mut TestArgs) {
        static mut BUF: [u64; 32] = [0; 32];
        unsafe {
            BUF.iter_mut()
                .for_each(|word| *word = ta.rng.gen_range(1..u64::MAX - 1))
        };

        let mut flash: Flash = Flash::unlock(&mut ta.flash);

        let start: u32 = DWT::cycle_count();
        unwrap!(unsafe { flash.fast_program(BUF.as_ptr(), ta.addr as *mut u64) });
        let end: u32 = DWT::cycle_count();
        let elapsed: u32 = end.wrapping_sub(start);

        defmt::info!(
            "256B program duration: {=u32:us} seconds",
            elapsed / CYC_PER_MICRO
        );

        for (idx, &dw) in unsafe { BUF }.iter().enumerate() {
            let expected: u64 = unsafe {
                (ta.addr as *const u64)
                    .offset(unwrap!(idx.try_into()))
                    .read_volatile()
            };
            defmt::assert_eq!(dw, expected);
        }

        // increment address by program size
        ta.addr += 256;
    }

    #[test]
    fn standard_program(ta: &mut TestArgs) {
        let data: u64 = ta.rng.gen_range(1..u64::MAX - 1);
        defmt::assert_ne!(data, u64::MAX);
        defmt::assert_ne!(data, 0);

        defmt::info!("Writing {:#016X} to {:#08X}", data, ta.addr);

        defmt::assert_eq!(unsafe { read_volatile(ta.addr as *const u64) }, u64::MAX);

        let mut flash: Flash = Flash::unlock(&mut ta.flash);

        let start: u32 = DWT::cycle_count();
        unwrap!(unsafe { flash.standard_program(&data, ta.addr as *mut u64) });
        let end: u32 = DWT::cycle_count();
        let elapsed: u32 = end.wrapping_sub(start);

        defmt::info!(
            "8B program duration: {=u32:us} seconds",
            elapsed / CYC_PER_MICRO
        );

        defmt::assert_eq!(unsafe { read_volatile(ta.addr as *const u64) }, data);

        // increment address by program size
        ta.addr += size_of::<u64>();
    }

    #[test]
    fn standard_program_generic_zero_size(ta: &mut TestArgs) {
        type ZeroSizeType = ();

        sa::assert_eq_size!(ZeroSizeType, [u8; 0]);

        let my_zero_size_type: ZeroSizeType = ();

        let mut flash: Flash = Flash::unlock(&mut ta.flash);

        // check flash is erased
        defmt::assert_eq!(unsafe { read_volatile(ta.addr as *const u64) }, u64::MAX);

        unwrap!(unsafe {
            flash.standard_program_generic(&my_zero_size_type, ta.addr as *mut ZeroSizeType)
        });

        // check flash was not modified
        defmt::assert_eq!(unsafe { read_volatile(ta.addr as *const u64) }, u64::MAX);
    }

    #[test]
    fn standard_program_generic(ta: &mut TestArgs) {
        #[derive(defmt::Format, PartialEq, Eq)]
        struct Keys {
            eui: [u8; 8],
            key: [u8; 16],
        }

        #[derive(defmt::Format, PartialEq, Eq)]
        #[repr(align(8))]
        struct TestStruct {
            connected: bool,
            keys: Keys,
            framecount_down: u32,
            framecount_up: u32,
        }

        sa::assert_eq_align!(TestStruct, u64);

        let data = TestStruct {
            connected: false,
            keys: Keys {
                eui: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                key: [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05,
                    0x06, 0x07, 0x08,
                ],
            },
            framecount_up: 12,
            framecount_down: 120,
        };

        defmt::info!("Writing {} to {:#08X}", data, ta.addr);

        let mut flash: Flash = Flash::unlock(&mut ta.flash);

        let start: u32 = DWT::cycle_count();
        unwrap!(unsafe { flash.standard_program_generic(&data, ta.addr as *mut TestStruct) });
        let end: u32 = DWT::cycle_count();
        let elapsed: u32 = end.wrapping_sub(start);

        let size = core::mem::size_of::<TestStruct>();

        defmt::info!(
            "{}B program duration: {=u32:us} seconds",
            size,
            elapsed / CYC_PER_MICRO
        );

        defmt::assert_eq!(unsafe { read_volatile(ta.addr as *const TestStruct) }, data);
    }
}
