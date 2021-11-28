//! Flash memory

use crate::pac;
use core::{ops::Range, ptr::write_volatile};

/// Starting address of the flash memory.
pub const FLASH_START: usize = 0x0800_0000;

/// Ending address of the flash memory.
///
/// This is calculated at runtime using the info registers.
///
/// # Example
///
/// ```no_run
/// use stm32wlxx_hal::flash::flash_end;
///
/// // valid for the nucleo-wl55jc with 256k flash
/// assert_eq!(flash_end(), 0x0803_FFFF);
/// ```
#[inline]
pub fn flash_end() -> usize {
    const OFFSET: usize = FLASH_START - 1;
    OFFSET + crate::info::flash_size() as usize
}

/// Number of flash pages.
///
/// This is calculated at runtime using the info registers.
///
/// # Example
///
/// ```no_run
/// use stm32wlxx_hal::flash::num_pages;
///
/// // valid for the nucleo-wl55jc with 256k flash
/// assert_eq!(num_pages(), 0x80);
/// ```
#[inline]
pub fn num_pages() -> u8 {
    (crate::info::flash_size_kibibyte() / 2) as u8
}

// status register (SR) flags
mod flags {
    pub const PROGERR: u32 = 1 << 3;
    pub const WRPERR: u32 = 1 << 4;
    pub const PGAERR: u32 = 1 << 5;
    pub const SIZERR: u32 = 1 << 6;
    pub const PGSERR: u32 = 1 << 7;
    pub const MISSERR: u32 = 1 << 8;
    pub const BSY: u32 = 1 << 16;
    pub const PESD: u32 = 1 << 19;
}

/// Page address.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub struct Page {
    idx: u8,
}

impl Page {
    /// Page size in bytes.
    pub const SIZE: usize = 2048;

    /// Create a page address from an index without checking bounds.
    ///
    /// # Safety
    ///
    /// 1. The `idx` argument must point to a valid flash page.
    #[inline]
    pub const unsafe fn from_index_unchecked(idx: u8) -> Self {
        Page { idx }
    }

    /// Create a page address from an index.
    ///
    /// Returns `None` if the value index is greater than the index of the last
    /// page, for example `0x7F` (page 127) on the STM32WLE5.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stm32wlxx_hal::flash::Page;
    ///
    /// assert!(Page::from_index(8).is_some());
    /// assert!(Page::from_index(128).is_none());
    /// ```
    pub fn from_index(idx: u8) -> Option<Self> {
        if idx >= num_pages() {
            None
        } else {
            Some(Page { idx })
        }
    }

    /// Create a page address from an offset from the base of the flash memory.
    ///
    /// Returns `None` if the address is out of bounds, or not page aligned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stm32wlxx_hal::flash::Page;
    ///
    /// assert_eq!(Page::from_byte_offset(0), Page::from_index(0));
    /// assert_eq!(Page::from_byte_offset(2048), Page::from_index(1));
    /// assert!(Page::from_byte_offset(2047).is_none());
    /// assert!(Page::from_byte_offset(usize::MAX).is_none());
    /// ```
    pub fn from_byte_offset(offset: usize) -> Option<Self> {
        if offset % Self::SIZE == 0 {
            let idx: usize = offset / Self::SIZE;
            if idx >= usize::from(num_pages()) {
                None
            } else {
                Some(Page { idx: idx as u8 })
            }
        } else {
            None
        }
    }

    /// Create a page address from an absolute address.
    ///
    /// Returns `None` if the address is out of bounds, or not page aligned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stm32wlxx_hal::flash::Page;
    ///
    /// assert_eq!(Page::from_addr(0x0800_0000), Page::from_index(0));
    /// assert_eq!(Page::from_addr(0x0800_0800), Page::from_index(1));
    /// assert!(Page::from_addr(0).is_none());
    /// assert!(Page::from_addr(usize::MAX).is_none());
    /// assert!(Page::from_addr(0x0800_0001).is_none());
    /// ```
    pub fn from_addr(addr: usize) -> Option<Self> {
        if let Some(offset) = addr.checked_sub(FLASH_START) {
            Self::from_byte_offset(offset)
        } else {
            None
        }
    }

    /// Get the page index.
    ///
    /// # Example
    ///
    /// ```
    /// # let page7 = unsafe { Page::from_index_unchecked(7) };
    /// use stm32wlxx_hal::flash::Page;
    ///
    /// assert_eq!(page7.to_index(), 7);
    /// ```
    #[inline]
    pub const fn to_index(self) -> u8 {
        self.idx
    }

    /// Get the page address.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # let page127 = unsafe { Page::from_index_unchecked(127) };
    /// # let page0 = unsafe { Page::from_index_unchecked(0) };
    /// use stm32wlxx_hal::flash::Page;
    ///
    /// assert_eq!(page0.addr(), 0x0800_0000);
    /// assert_eq!(page127.addr(), 0x0803_F800);
    /// ```
    pub const fn addr(&self) -> usize {
        (self.idx as usize) * Self::SIZE + FLASH_START
    }

    /// Get the address range of the page.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # let page0 = unsafe { Page::from_index_unchecked(0) };
    /// use core::ops::Range;
    /// use stm32wlxx_hal::flash::Page;
    ///
    /// assert_eq!(
    ///     page0.addr_range(),
    ///     Range {
    ///         start: 0x0800_0000,
    ///         end: 0x0800_07FF
    ///     }
    /// );
    /// ```
    pub const fn addr_range(&self) -> Range<usize> {
        Range {
            start: self.addr(),
            end: self.addr() + (Page::SIZE - 1),
        }
    }
}

/// Flash errors.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Busy Error.
    ///
    /// A flash programming sequence was started while the previous sequence
    /// was still in-progress.
    Busy,
    /// Program erase suspend error.
    ///
    /// A flash programming sequence was started with a program erase suspend
    /// bit set.
    Suspend,
    /// Fast programming data miss error.
    ///
    /// In Fast programming mode, 32 double-words (256 bytes) must be sent to
    /// the flash memory successively and the new data must be sent to the logic
    /// control before the current data is fully programmed.
    ///
    /// This bit is set by hardware when the new data is not present in time.
    Miss,
    /// Programming sequence error.
    ///
    /// This bit is set by hardware when a write access to the flash memory is
    /// performed by the code, while PG or FSTPG have not been set previously.
    ///
    /// This bit is also set by hardware when PROGERR, SIZERR, PGAERR, WRPERR,
    /// MISSERR or FASTERR is set due to a previous programming error.
    Seq,
    /// Size error.
    ///
    /// This bit is set by hardware when the size of the access is a byte (`u8`)
    /// or half-word (`u16`) during a program or a fast program sequence.
    /// Only double-word (`u64`) programming is allowed (consequently: word (`u32`) access).
    Size,
    /// Programming alignment error.
    ///
    /// This bit is set by hardware when the data to program cannot be contained in the same
    /// double-word (`u64`) Flash memory in case of standard programming, or if there is a change
    /// of page during fast programming.
    Align,
    /// Write protection error.
    ///
    /// An address to be erased/programmed belongs to a write-protected part
    /// (by WRP, PCROP or RDP level 1) of the flash memory.
    Wp,
    /// Programming error.
    ///
    /// A 64-bit address to be programmed contains a value different from
    /// `0xFFFF_FFFF_FFFF_FFFF` before programming, except if the data to write
    /// is `0x0000_0000_0000_0000`.
    ///
    /// The erratum states that this will also occur when programming
    /// `0x0000_0000_0000_0000` to a location previously programmed with
    /// `0xFFFF_FFFF_FFFF_FFFF`.
    Prog,
}

/// Flash driver.
#[derive(Debug)]
pub struct Flash<'a> {
    flash: &'a mut pac::FLASH,
}

impl Drop for Flash<'_> {
    fn drop(&mut self) {
        // despite what RM0453 Rev 2 says there is no separate lock for core 2
        // as far as I can tell
        self.flash.cr.modify(|_, w| w.lock().set_bit())
    }
}

impl<'a> Flash<'a> {
    /// Unlock the flash memory for program or erase operations.
    ///
    /// The flash memory will be locked when this struct is dropped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stm32wlxx_hal::{flash::Flash, pac};
    ///
    /// let mut dp: pac::Peripherals = pac::Peripherals::take().unwrap();
    ///
    /// let mut flash: Flash = Flash::unlock(&mut dp.FLASH);
    /// ```
    pub fn unlock(flash: &'a mut pac::FLASH) -> Self {
        flash.keyr.write(|w| w.key().bits(0x4567_0123));
        flash.keyr.write(|w| w.key().bits(0xCDEF_89AB));
        Self { flash }
    }

    #[inline(always)]
    fn sr(&self) -> u32 {
        c1_c2!(self.flash.sr.read().bits(), self.flash.c2sr.read().bits())
    }

    #[rustfmt::skip]
    #[inline(always)]
    fn clear_all_err(&mut self) {
        c1_c2!(
            self.flash.sr.write(|w| {
                w
                    .rderr().clear()
                    .fasterr().clear()
                    .misserr().clear()
                    .pgserr().clear()
                    .sizerr().clear()
                    .pgaerr().clear()
                    .wrperr().clear()
                    .progerr().clear()
                    .operr().clear()
                    .eop().clear()
            }),
            self.flash.c2sr.write(|w| {
                w
                    .rderr().clear()
                    .fasterr().clear()
                    .misserr().clear()
                    .pgserr().clear()
                    .sizerr().clear()
                    .pgaerr().clear()
                    .wrperr().clear()
                    .progerr().clear()
                    .operr().clear()
                    .eop().clear()
            }),
        )
    }

    #[inline(always)]
    fn wait_for_not_busy(&self) -> Result<(), Error> {
        loop {
            let sr: u32 = self.sr();

            // "This bit is set at the beginning of a Flash operation and
            // reset when the operation finishes or when an error occurs."
            if sr & flags::BSY == 0 {
                if sr & flags::PROGERR == flags::PROGERR {
                    return Err(Error::Prog);
                }
                if sr & flags::WRPERR == flags::WRPERR {
                    return Err(Error::Wp);
                }
                if sr & flags::PGAERR == flags::PGAERR {
                    return Err(Error::Align);
                }
                if sr & flags::SIZERR == flags::SIZERR {
                    return Err(Error::Size);
                }
                if sr & flags::MISSERR == flags::MISSERR {
                    return Err(Error::Miss);
                }
                // check last because it can be set with other flags
                if sr & flags::PGSERR == flags::PGSERR {
                    return Err(Error::Seq);
                }

                return Ok(());
            }
        }
    }

    /// Program 8 bytes.
    ///
    /// # Safety
    ///
    /// 1. Do not write to flash memory that is being used for your code.
    /// 2. The destination address must be within the flash memory region.
    /// 3. The `from` and `to` pointers must be aligned to the pointee type.
    #[allow(unused_unsafe)]
    pub unsafe fn standard_program(&mut self, from: *const u64, to: *mut u64) -> Result<(), Error> {
        let sr: u32 = self.sr();
        if sr & flags::BSY != 0 {
            return Err(Error::Busy);
        }
        if sr & flags::PESD != 0 {
            return Err(Error::Suspend);
        }

        self.clear_all_err();

        c1_c2!(
            self.flash.cr.modify(|_, w| w.pg().set_bit()),
            self.flash.c2cr.modify(|_, w| w.pg().set_bit())
        );

        unsafe {
            write_volatile(to as *mut u32, (from as *const u32).read());
            write_volatile(
                (to as *mut u32).offset(1),
                (from as *const u32).offset(1).read(),
            );
        }

        let ret: Result<(), Error> = self.wait_for_not_busy();

        c1_c2!(
            self.flash.cr.modify(|_, w| w.pg().clear_bit()),
            self.flash.c2cr.modify(|_, w| w.pg().clear_bit())
        );

        ret
    }

    /// Program 256 bytes.
    ///
    /// # Safety
    ///
    /// 1. Do not write to flash memory that is being used for your code.
    /// 2. The destination address must be within the flash memory region.
    /// 3. The flash clock frequency (HCLK3) must be at least 8 MHz.
    /// 4. The `from` and `to` pointers must be aligned to the pointee type.
    /// 5. The `from` pointer must point to 256 bytes of valid data.
    /// 6. The CPU must execute this from SRAM.
    ///    The compiler may inline this function, because `#[inline(never)]` is
    ///    merely a suggestion.
    #[allow(unused_unsafe)]
    #[cfg_attr(target_os = "none", link_section = ".data")]
    #[inline(never)]
    pub unsafe fn fast_program(&mut self, from: *const u64, to: *mut u64) -> Result<(), Error> {
        let sr: u32 = self.sr();
        if sr & flags::BSY != 0 {
            return Err(Error::Busy);
        }
        if sr & flags::PESD != 0 {
            return Err(Error::Suspend);
        }

        self.clear_all_err();

        c1_c2!(
            self.flash.cr.modify(|_, w| w.fstpg().set_bit()),
            self.flash.c2cr.modify(|_, w| w.fstpg().set_bit())
        );

        let from: *const u32 = from as *const u32;
        let to: *mut u32 = to as *mut u32;

        (0..64)
            .into_iter()
            .for_each(|word| unsafe { write_volatile(to.offset(word), from.offset(word).read()) });

        let ret: Result<(), Error> = self.wait_for_not_busy();

        c1_c2!(
            self.flash.cr.modify(|_, w| w.fstpg().clear_bit()),
            self.flash.c2cr.modify(|_, w| w.fstpg().clear_bit())
        );

        ret
    }

    /// Erases a 2048 byte page, setting all the bits to `1`.
    ///
    /// # Safety
    ///
    /// 1. Do not erase flash memory that is being used for your code.
    pub unsafe fn page_erase(&mut self, page: Page) -> Result<(), Error> {
        let sr: u32 = self.sr();
        if sr & flags::BSY != 0 {
            return Err(Error::Busy);
        }
        if sr & flags::PESD != 0 {
            return Err(Error::Suspend);
        }

        self.clear_all_err();

        c1_c2!(
            self.flash.cr.modify(|_, w| w
                .per()
                .set_bit()
                .pnb()
                .bits(page.to_index())
                .strt()
                .set_bit()),
            self.flash.c2cr.modify(|_, w| w
                .per()
                .set_bit()
                .pnb()
                .bits(page.to_index())
                .strt()
                .set_bit())
        );

        let ret: Result<(), Error> = self.wait_for_not_busy();

        c1_c2!(
            self.flash.cr.modify(|_, w| w.per().clear_bit()),
            self.flash.c2cr.modify(|_, w| w.per().clear_bit())
        );

        ret
    }

    /// Erases the entire flash memory, setting all the bits to `1`.
    ///
    /// # Safety
    ///
    /// 1. The CPU must execute this from SRAM.
    ///    The compiler may inline this function, because `#[inline(never)]` is
    ///    merely a suggestion.
    #[cfg_attr(target_os = "none", link_section = ".data")]
    #[inline(never)]
    pub unsafe fn mass_erase(&mut self) -> Result<(), Error> {
        let sr: u32 = self.sr();
        if sr & flags::BSY != 0 {
            return Err(Error::Busy);
        }
        if sr & flags::PESD != 0 {
            return Err(Error::Suspend);
        }

        self.clear_all_err();

        c1_c2!(
            self.flash
                .cr
                .modify(|_, w| w.mer().set_bit().strt().set_bit()),
            self.flash
                .c2cr
                .modify(|_, w| w.mer().set_bit().strt().set_bit())
        );

        let ret: Result<(), Error> = self.wait_for_not_busy();

        c1_c2!(
            self.flash.cr.modify(|_, w| w.mer().clear_bit()),
            self.flash.c2cr.modify(|_, w| w.mer().clear_bit())
        );

        ret
    }
}
