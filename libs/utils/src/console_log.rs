//! Console log codes (audit-api-spec.md §9.4): Pro's, and ours from `iop` 23 and `typ` 4.
pub const TYP_GROUP: i16 = 0;
pub const TYP_USER: i16 = 1;
pub const TYP_DEVICE: i16 = 2;
pub const TYP_ADDRESS_BOOK: i16 = 3;
pub const TYP_POLICY: i16 = 4;

pub const IOP_ADD_GROUP: i16 = 1;
pub const IOP_ADD_USER: i16 = 2;
pub const IOP_DELETE_GROUPS: i16 = 4;
pub const IOP_DISCONNECT_DEVICE: i16 = 5;
pub const IOP_ENABLE_USERS: i16 = 6;
pub const IOP_DISABLE_USERS: i16 = 7;
pub const IOP_UPDATE_GROUP: i16 = 10;
pub const IOP_UPDATE_USER: i16 = 11;
pub const IOP_DELETE_USER: i16 = 13;
pub const IOP_ADD_ADDRESS_BOOK: i16 = 15;
pub const IOP_DELETE_ADDRESS_BOOK: i16 = 16;
pub const IOP_CHANGE_ADDRESS_BOOK_NAME: i16 = 17;
pub const IOP_ADD_AB_PERMISSION: i16 = 20;
pub const IOP_DELETE_AB_PERMISSION: i16 = 21;
pub const IOP_PROMOTE_ADMIN: i16 = 23;
pub const IOP_DEMOTE_ADMIN: i16 = 24;
pub const IOP_UPDATE_POLICY: i16 = 25;
pub const IOP_REPUSH_POLICY: i16 = 26;
