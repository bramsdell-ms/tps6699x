//! `VDMs`: PD send VDM
//!
//! The 'VDMs' Task instructs PD Controller to send a Vendor Defined Message (VDM)
//! at the first opportunity while maintaining policy engine compliance.
//!
//! # Usage Examples
//!
//! ## Sending a Structured VDM (SVDM)
//!
//! ```no_run
//! use tps6699x::command::vdms::{Input, SopTarget};
//!
//! // Create an SVDM Discover Identity command
//! let discover_identity_header = 0xFF008001; // Example SVDM header
//! let vdm_input = Input::structured_vdm(
//!     discover_identity_header,
//!     &[], // No additional VDOs beyond header
//!     SopTarget::Sop,
//!     true // Initiating a new sequence
//! );
//! ```
//!
//! ## Sending an Unstructured VDM
//!
//! ```no_run
//! use tps6699x::command::vdms::{Input, SopTarget};
//!
//! let vendor_data = [0x12345678, 0x9ABCDEF0];
//! let vdm_input = Input::unstructured_vdm(
//!     &vendor_data,
//!     SopTarget::Sop,
//!     true // Initiating
//! );
//! ```
//!
//! ## Sending a Response VDM
//!
//! ```no_run
//! use tps6699x::command::vdms::{Input, SopTarget};
//!
//! // Create an ACK response
//! let ack_data = [0x87654321];
//! let vdm_input = Input::response(&ack_data, SopTarget::Sop);
//! ```
//!

use bincode::de::Decoder;
use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{Decode, Encode};
use bitfield::bitfield;

/// VDMs Task input data length (31 bytes)
pub const VDMS_INPUT_LEN: usize = 31;

/// Common SVDM Commands (for VDM Header bits 4:0)
pub mod svdm_commands {
    /// Reserved
    pub const RESERVED: u8 = 0x00;
    /// Discover Identity
    pub const DISCOVER_IDENTITY: u8 = 0x01;
    /// Discover SVIDs  
    pub const DISCOVER_SVIDS: u8 = 0x02;
    /// Discover Modes
    pub const DISCOVER_MODES: u8 = 0x03;
    /// Enter Mode
    pub const ENTER_MODE: u8 = 0x04;
    /// Exit Mode
    pub const EXIT_MODE: u8 = 0x05;
    /// Attention
    pub const ATTENTION: u8 = 0x06;
}

/// Common SVDM Command Types (for VDM Header bits 7:6)
pub mod svdm_command_type {
    /// Initiator Request
    pub const REQ: u8 = 0x0;
    /// Responder ACK
    pub const ACK: u8 = 0x1;
    /// Responder NAK
    pub const NAK: u8 = 0x2;
    /// Responder BUSY
    pub const BUSY: u8 = 0x3;
}

/// Helper function to create an SVDM header
///
/// # Arguments
/// * `svid` - Standard or Vendor ID (bits 31:16)
/// * `vdm_type` - 0 for Unstructured, 1 for Structured (bit 15)
/// * `svdm_version` - SVDM Version (bits 14:13), typically 0x0 for 1.0, 0x1 for 2.0
/// * `object_position` - Object Position (bits 10:8), 0 for commands that don't use positions
/// * `command_type` - Command Type (bits 7:6) from `svdm_command_type`
/// * `command` - Command (bits 4:0) from `svdm_commands`
///
/// # Returns
/// A u32 containing the formatted SVDM header
pub fn create_svdm_header(
    svid: u16,
    vdm_type: u8,
    svdm_version: u8,
    object_position: u8,
    command_type: u8,
    command: u8,
) -> u32 {
    ((svid as u32) << 16)
        | ((vdm_type as u32 & 0x1) << 15)
        | ((svdm_version as u32 & 0x3) << 13)
        | ((object_position as u32 & 0x7) << 8)
        | ((command_type as u32 & 0x3) << 6)
        | (command as u32 & 0x1F)
}

/// SOP target for the VDM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SopTarget {
    /// SOP
    Sop = 0x00,
    /// SOP'
    SopPrime = 0x01,
    /// SOP''
    SopDoublePrime = 0x02,
    /// SOP*_Debug (SOP'_Debug for Source, SOP''_Debug for Sink)
    SopDebug = 0x03,
}

impl From<SopTarget> for u8 {
    fn from(val: SopTarget) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for SopTarget {
    type Error = crate::PdError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SopTarget::Sop),
            0x01 => Ok(SopTarget::SopPrime),
            0x02 => Ok(SopTarget::SopDoublePrime),
            0x03 => Ok(SopTarget::SopDebug),
            _ => Err(crate::PdError::InvalidParams),
        }
    }
}

bitfield! {
    /// The VDMs Task Header (byte 0)
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct VdmsTaskHeader(u8);
    impl Debug;

    /// AMIntrusiveModeResponse: When set this message satisfies a pending AMIntrusiveMode
    /// interaction, PD Controller will stop sending BUSY Responses to the last received SVDM command.
    pub bool, am_intrusive_mode_response, set_am_intrusive_mode_response: 7;

    /// Reserved (write as 0b)
    u8, _reserved_6, _set_reserved_6: 6;

    /// SOPTarget: Ordered Set to send VDM to
    pub u8, sop_target, set_sop_target: 5, 4;

    /// Version: To maintain backwards compatibility, this field is used to indicate
    /// whether bytes 30-31 are ignored or used.
    /// 0b VDMs version 1 (ignores bytes 30-31). The PD controller always waits 30ms for a response.
    /// 1b VDMs version 2 (implements bytes 30-31)
    pub bool, version, set_version: 3;

    /// NumDOs: Number of VDOs to transmit (1-7), includes VDM Header for SVDMs.
    pub u8, num_dos, set_num_dos: 2, 0;
}

bitfield! {
    /// The VDMs Configuration (byte 29)
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct VdmsConfiguration(u8);
    impl Debug;

    /// Reserved
    u8, _reserved, _set_reserved: 7, 1;

    /// InitiatorResponder: The VDMs can be sending a response or initiating a sequence.
    /// 0b This is a response so the PD controller will transmit the message regardless
    ///    of the collision avoidance Rp value. Example, an ACK message is responding.
    /// 1b This is initiating a VDM sequence, so the PD controller will follow USB PD
    ///    collision avoidance requirements. Example, a REQ message is initiating a new VDM sequence.
    pub bool, initiator_responder, set_initiator_responder: 0;
}

/// The input data for the `VDMs` command.
///
/// This structure represents the full 31-byte input data for sending Vendor Defined Messages.
/// The data is organized according to the TPS6699x manual specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Input {
    /// VDMs Task Header (byte 0)
    pub header: VdmsTaskHeader,
    /// VDO #1 - Contents of first VDO (VDM Header if SVDM) (bytes 1-4)
    pub vdo1: u32,
    /// VDO #2 - Contents of second VDO, if applicable (bytes 5-8)
    pub vdo2: u32,
    /// VDO #3 - Contents of third VDO, if applicable (bytes 9-12)
    pub vdo3: u32,
    /// VDO #4 - Contents of fourth VDO, if applicable (bytes 13-16)
    pub vdo4: u32,
    /// VDO #5 - Contents of fifth VDO, if applicable (bytes 17-20)
    pub vdo5: u32,
    /// VDO #6 - Contents of sixth VDO, if applicable (bytes 21-24)
    pub vdo6: u32,
    /// VDO #7 - Contents of seventh VDO, if applicable (bytes 25-28)
    pub vdo7: u32,
    /// VDMs Configuration (byte 29)
    pub configuration: VdmsConfiguration,
    /// Initiator Wait State Timer Configuration (byte 30)
    /// Configurable Initiator Wait State Timer. Please note, this timer is only
    /// used if the InitiatorResponder bit in byte 29 is set to 1b. The PD
    /// controller will wait for this amount of time for a response. (1ms per LSB)
    pub initiator_wait_timer: u8,
}

impl Input {
    /// Create a new VDMs input with default values
    pub fn new() -> Self {
        Self {
            header: VdmsTaskHeader(0),
            vdo1: 0,
            vdo2: 0,
            vdo3: 0,
            vdo4: 0,
            vdo5: 0,
            vdo6: 0,
            vdo7: 0,
            configuration: VdmsConfiguration(0),
            initiator_wait_timer: 30, // Default 30ms wait
        }
    }

    /// Create a VDM for sending a Structured VDM (SVDM)
    ///
    /// # Arguments
    /// * `header` - The VDM header containing command, SVID, etc.
    /// * `vdos` - Additional VDOs (beyond the header)
    /// * `sop_target` - Which SOP to target (SOP, SOP', SOP'', etc.)
    /// * `is_initiator` - true if initiating a new sequence, false if responding
    pub fn structured_vdm(header: u32, vdos: &[u32], sop_target: SopTarget, is_initiator: bool) -> Self {
        let input = Self::new();

        // Build the full VDO list with header first
        let mut all_vdos = [0u32; 7];
        all_vdos[0] = header;
        let additional_count = vdos.len().min(6);
        all_vdos[1..=additional_count].copy_from_slice(&vdos[..additional_count]);

        input
            .with_vdos(&all_vdos[..=additional_count])
            .with_sop_target(sop_target)
            .with_initiator_responder(is_initiator)
            .with_version_2()
    }

    /// Create a VDM for sending an Unstructured VDM
    ///
    /// # Arguments
    /// * `vdos` - The VDOs to send
    /// * `sop_target` - Which SOP to target (SOP, SOP', SOP'', etc.)
    /// * `is_initiator` - true if initiating a new sequence, false if responding
    pub fn unstructured_vdm(vdos: &[u32], sop_target: SopTarget, is_initiator: bool) -> Self {
        Self::new()
            .with_vdos(vdos)
            .with_sop_target(sop_target)
            .with_initiator_responder(is_initiator)
            .with_version_2()
    }

    /// Create a VDM response (not initiating a sequence)
    pub fn response(vdos: &[u32], sop_target: SopTarget) -> Self {
        Self::new()
            .with_vdos(vdos)
            .with_sop_target(sop_target)
            .with_initiator_responder(false) // Response
    }

    /// Set the number of VDOs to transmit (1-7)
    pub fn with_num_dos(mut self, num_dos: u8) -> Self {
        if num_dos > 0 && num_dos <= 7 {
            self.header.set_num_dos(num_dos);
        }
        self
    }

    /// Set the SOP target for the VDM
    pub fn with_sop_target(mut self, target: SopTarget) -> Self {
        self.header.set_sop_target(target as u8);
        self
    }

    /// Set version 2 to enable initiator wait timer
    pub fn with_version_2(mut self) -> Self {
        self.header.set_version(true);
        self
    }

    /// Set AMIntrusiveModeResponse flag
    pub fn with_am_intrusive_mode_response(mut self) -> Self {
        self.header.set_am_intrusive_mode_response(true);
        self
    }

    /// Set as initiator (true) or responder (false)
    pub fn with_initiator_responder(mut self, is_initiator: bool) -> Self {
        self.configuration.set_initiator_responder(is_initiator);
        self
    }

    /// Set the initiator wait timer (in milliseconds, only used in version 2)
    pub fn with_initiator_wait_timer(mut self, timer_ms: u8) -> Self {
        self.initiator_wait_timer = timer_ms;
        self
    }

    /// Set VDO data (up to 7 VDOs)
    pub fn with_vdos(mut self, vdos: &[u32]) -> Self {
        let count = vdos.len().min(7);
        self.header.set_num_dos(count as u8);

        if count > 0 {
            self.vdo1 = vdos[0];
        }
        if count > 1 {
            self.vdo2 = vdos[1];
        }
        if count > 2 {
            self.vdo3 = vdos[2];
        }
        if count > 3 {
            self.vdo4 = vdos[3];
        }
        if count > 4 {
            self.vdo5 = vdos[4];
        }
        if count > 5 {
            self.vdo6 = vdos[5];
        }
        if count > 6 {
            self.vdo7 = vdos[6];
        }

        self
    }

    /// Get the VDO data as an array
    pub fn vdos(&self) -> [u32; 7] {
        [
            self.vdo1, self.vdo2, self.vdo3, self.vdo4, self.vdo5, self.vdo6, self.vdo7,
        ]
    }

    /// Get the number of VDOs
    pub fn num_dos(&self) -> u8 {
        self.header.num_dos()
    }

    /// Get the SOP target
    pub fn sop_target(&self) -> Result<SopTarget, crate::PdError> {
        SopTarget::try_from(self.header.sop_target())
    }

    /// Check if this is version 2 (with extended features)
    pub fn is_version_2(&self) -> bool {
        self.header.version()
    }

    /// Check if AMIntrusiveModeResponse is set
    pub fn am_intrusive_mode_response(&self) -> bool {
        self.header.am_intrusive_mode_response()
    }

    /// Check if this is an initiator (true) or responder (false)
    pub fn is_initiator(&self) -> bool {
        self.configuration.initiator_responder()
    }
}

impl Default for Input {
    fn default() -> Self {
        Self::new()
    }
}

impl Encode for Input {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // Byte 0: VDMs Task Header
        Encode::encode(&self.header.0, encoder)?;
        // Bytes 1-4: VDO #1 (little endian)
        Encode::encode(&self.vdo1, encoder)?;
        // Bytes 5-8: VDO #2 (little endian)
        Encode::encode(&self.vdo2, encoder)?;
        // Bytes 9-12: VDO #3 (little endian)
        Encode::encode(&self.vdo3, encoder)?;
        // Bytes 13-16: VDO #4 (little endian)
        Encode::encode(&self.vdo4, encoder)?;
        // Bytes 17-20: VDO #5 (little endian)
        Encode::encode(&self.vdo5, encoder)?;
        // Bytes 21-24: VDO #6 (little endian)
        Encode::encode(&self.vdo6, encoder)?;
        // Bytes 25-28: VDO #7 (little endian)
        Encode::encode(&self.vdo7, encoder)?;
        // Byte 29: VDMs Configuration
        Encode::encode(&self.configuration.0, encoder)?;
        // Byte 30: Initiator Wait State Timer Configuration
        Encode::encode(&self.initiator_wait_timer, encoder)?;
        Ok(())
    }
}

impl<Context> Decode<Context> for Input {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let header = VdmsTaskHeader(Decode::decode(decoder)?);
        let vdo1 = Decode::decode(decoder)?;
        let vdo2 = Decode::decode(decoder)?;
        let vdo3 = Decode::decode(decoder)?;
        let vdo4 = Decode::decode(decoder)?;
        let vdo5 = Decode::decode(decoder)?;
        let vdo6 = Decode::decode(decoder)?;
        let vdo7 = Decode::decode(decoder)?;
        let configuration = VdmsConfiguration(Decode::decode(decoder)?);
        let initiator_wait_timer = Decode::decode(decoder)?;

        Ok(Input {
            header,
            vdo1,
            vdo2,
            vdo3,
            vdo4,
            vdo5,
            vdo6,
            vdo7,
            configuration,
            initiator_wait_timer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config;

    #[test]
    fn test_vdms_input_creation() {
        let input = Input::new()
            .with_num_dos(3)
            .with_sop_target(SopTarget::Sop)
            .with_version_2()
            .with_vdos(&[0x12345678, 0x9ABCDEF0, 0x11223344])
            .with_initiator_responder(true)
            .with_initiator_wait_timer(50);

        assert_eq!(input.num_dos(), 3);
        assert_eq!(input.sop_target().unwrap(), SopTarget::Sop);
        assert_eq!(input.is_version_2(), true);
        assert_eq!(input.is_initiator(), true);
        assert_eq!(input.initiator_wait_timer, 50);
        assert_eq!(input.vdo1, 0x12345678);
        assert_eq!(input.vdo2, 0x9ABCDEF0);
        assert_eq!(input.vdo3, 0x11223344);
    }

    #[test]
    fn test_vdms_input_encode_decode() {
        let original = Input::new()
            .with_num_dos(2)
            .with_sop_target(SopTarget::SopPrime)
            .with_vdos(&[0x12345678, 0x9ABCDEF0])
            .with_initiator_responder(false);

        let mut buf = [0u8; VDMS_INPUT_LEN];
        bincode::encode_into_slice(original, &mut buf, config::standard().with_fixed_int_encoding()).unwrap();

        let (decoded, _): (Input, _) =
            bincode::decode_from_slice(&buf, config::standard().with_fixed_int_encoding()).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_sop_target_conversion() {
        assert_eq!(SopTarget::Sop as u8, 0x00);
        assert_eq!(SopTarget::SopPrime as u8, 0x01);
        assert_eq!(SopTarget::SopDoublePrime as u8, 0x02);
        assert_eq!(SopTarget::SopDebug as u8, 0x03);

        assert_eq!(SopTarget::try_from(0x00).unwrap(), SopTarget::Sop);
        assert_eq!(SopTarget::try_from(0x01).unwrap(), SopTarget::SopPrime);
        assert_eq!(SopTarget::try_from(0x02).unwrap(), SopTarget::SopDoublePrime);
        assert_eq!(SopTarget::try_from(0x03).unwrap(), SopTarget::SopDebug);

        assert!(SopTarget::try_from(0x04).is_err());
    }

    #[test]
    fn test_bitfield_operations() {
        let mut header = VdmsTaskHeader(0);
        header.set_num_dos(5);
        header.set_sop_target(SopTarget::SopPrime as u8);
        header.set_version(true);
        header.set_am_intrusive_mode_response(true);

        assert_eq!(header.num_dos(), 5);
        assert_eq!(header.sop_target(), SopTarget::SopPrime as u8);
        assert_eq!(header.version(), true);
        assert_eq!(header.am_intrusive_mode_response(), true);

        let mut config = VdmsConfiguration(0);
        config.set_initiator_responder(true);
        assert_eq!(config.initiator_responder(), true);
    }

    #[test]
    fn test_structured_vdm_creation() {
        let header = 0x12345678; // Mock SVDM header
        let vdos = [0x9ABCDEF0, 0x11223344];

        let input = Input::structured_vdm(header, &vdos, SopTarget::Sop, true);

        assert_eq!(input.num_dos(), 3); // Header + 2 VDOs
        assert_eq!(input.vdo1, header);
        assert_eq!(input.vdo2, vdos[0]);
        assert_eq!(input.vdo3, vdos[1]);
        assert_eq!(input.sop_target().unwrap(), SopTarget::Sop);
        assert_eq!(input.is_initiator(), true);
        assert_eq!(input.is_version_2(), true);
    }

    #[test]
    fn test_unstructured_vdm_creation() {
        let vdos = [0x12345678, 0x9ABCDEF0];

        let input = Input::unstructured_vdm(&vdos, SopTarget::SopPrime, false);

        assert_eq!(input.num_dos(), 2);
        assert_eq!(input.vdo1, vdos[0]);
        assert_eq!(input.vdo2, vdos[1]);
        assert_eq!(input.sop_target().unwrap(), SopTarget::SopPrime);
        assert_eq!(input.is_initiator(), false);
        assert_eq!(input.is_version_2(), true);
    }

    #[test]
    fn test_response_vdm_creation() {
        let vdos = [0x87654321];

        let input = Input::response(&vdos, SopTarget::SopDoublePrime);

        assert_eq!(input.num_dos(), 1);
        assert_eq!(input.vdo1, vdos[0]);
        assert_eq!(input.sop_target().unwrap(), SopTarget::SopDoublePrime);
        assert_eq!(input.is_initiator(), false); // Response
    }

    #[test]
    fn test_svdm_header_creation() {
        use crate::command::vdms::{create_svdm_header, svdm_command_type, svdm_commands};

        // Create a Discover Identity REQ header for DisplayPort SVID
        let header = create_svdm_header(
            0xFF01, // DisplayPort SVID
            1,      // Structured VDM
            0,      // SVDM Version 1.0
            0,      // Object position 0 (not used for Discover Identity)
            svdm_command_type::REQ,
            svdm_commands::DISCOVER_IDENTITY,
        );

        // Verify the header format
        assert_eq!((header >> 16) & 0xFFFF, 0xFF01); // SVID
        assert_eq!((header >> 15) & 0x1, 1); // VDM Type (Structured)
        assert_eq!((header >> 13) & 0x3, 0); // SVDM Version
        assert_eq!((header >> 8) & 0x7, 0); // Object Position
        assert_eq!((header >> 6) & 0x3, svdm_command_type::REQ as u32); // Command Type
        assert_eq!(header & 0x1F, svdm_commands::DISCOVER_IDENTITY as u32); // Command
    }
}
