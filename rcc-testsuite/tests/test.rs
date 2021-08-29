// Most of the coverage for SPI comes from the Sub-GHz testsuite.

#![no_std]
#![no_main]

use defmt::unwrap;
use defmt_rtt as _; // global logger
use itertools::iproduct;
use panic_probe as _;
use stm32wl_hal::{
    cortex_m::{self, interrupt::CriticalSection},
    pac,
    rcc::{self, MsiRange, Vos},
};

#[derive(defmt::Format)]
pub enum SysClkSrc {
    Msi(MsiRange),
    Hse(Vos),
    Hsi,
}

impl SysClkSrc {
    pub unsafe fn set(
        &self,
        flash: &mut pac::FLASH,
        pwr: &mut pac::PWR,
        rcc: &mut pac::RCC,
        cs: &CriticalSection,
    ) {
        match self {
            SysClkSrc::Msi(range) => rcc::set_sysclk_msi(flash, pwr, rcc, *range, cs),
            SysClkSrc::Hse(vos) => rcc::set_sysclk_hse(flash, pwr, rcc, *vos, cs),
            SysClkSrc::Hsi => rcc::set_sysclk_hsi(flash, pwr, rcc, cs),
        }
    }

    pub fn to_hz(&self) -> u32 {
        match self {
            SysClkSrc::Msi(range) => range.to_hz(),
            SysClkSrc::Hse(vos) => match vos {
                Vos::V1_2 => 32_000_000,
                Vos::V1_0 => 16_000_000,
            },
            SysClkSrc::Hsi => 16_000_000,
        }
    }
}

const CLKS: [SysClkSrc; 14] = [
    SysClkSrc::Hsi,
    SysClkSrc::Hse(Vos::V1_0),
    SysClkSrc::Hse(Vos::V1_2),
    // STLink drops the connection when switching to 100k
    // works with a different probe
    // SysClkSrc::Msi(MsiRange::Range100k),
    SysClkSrc::Msi(MsiRange::Range200k),
    SysClkSrc::Msi(MsiRange::Range400k),
    SysClkSrc::Msi(MsiRange::Range800k),
    SysClkSrc::Msi(MsiRange::Range1M),
    SysClkSrc::Msi(MsiRange::Range2M),
    SysClkSrc::Msi(MsiRange::Range4M),
    SysClkSrc::Msi(MsiRange::Range8M),
    SysClkSrc::Msi(MsiRange::Range16M),
    SysClkSrc::Msi(MsiRange::Range24M),
    SysClkSrc::Msi(MsiRange::Range32M),
    SysClkSrc::Msi(MsiRange::Range48M),
];

// HardFault is a symptom of the MSI switching erratum
#[cortex_m_rt::exception]
#[allow(non_snake_case)]
fn HardFault(_ef: &cortex_m_rt::ExceptionFrame) -> ! {
    cortex_m::interrupt::disable();
    defmt::error!("HardFault");
    loop {
        cortex_m::asm::bkpt()
    }
}

#[defmt_test::tests]
mod tests {
    use super::*;

    struct TestArgs {
        flash: pac::FLASH,
        pwr: pac::PWR,
        rcc: pac::RCC,
    }

    #[init]
    fn init() -> TestArgs {
        let dp: pac::Peripherals = unwrap!(pac::Peripherals::take());

        TestArgs {
            rcc: dp.RCC,
            pwr: dp.PWR,
            flash: dp.FLASH,
        }
    }

    // exhaustive tests of sysclk switching from every possible source to every possible source
    #[test]
    fn sysclk_switching(ta: &mut TestArgs) {
        for (from, to) in iproduct!(CLKS.iter(), CLKS.iter()) {
            defmt::info!("from {} to {}", from, to);

            cortex_m::interrupt::free(|cs| unsafe {
                from.set(&mut ta.flash, &mut ta.pwr, &mut ta.rcc, cs)
            });
            defmt::assert_eq!(rcc::sysclk_hz(&ta.rcc), from.to_hz());

            cortex_m::interrupt::free(|cs| unsafe {
                to.set(&mut ta.flash, &mut ta.pwr, &mut ta.rcc, cs)
            });
            defmt::assert_eq!(rcc::sysclk_hz(&ta.rcc), to.to_hz());
        }
    }
}
