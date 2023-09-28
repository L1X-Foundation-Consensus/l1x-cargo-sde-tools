pub type Address = [u8; 20];
pub type Balance = u128;
pub type Decimal = u8;
pub type MemPoolSize = usize;
pub type TimeStamp = u128;
pub type Nonce = u128;
pub type IpAddress = Vec<u8>;
pub type BlockNumber = u128;
pub type BlockHash = [u8; 32];
pub type SignatureBytes = Vec<u8>;
pub type VerifyingKeyBytes = Vec<u8>;
pub type Metadata = Vec<u8>;
pub type ContractCode = Vec<u8>;
pub type ContractFunction = Vec<u8>;
pub type ContractArgument = Vec<u8>;
pub type ContractInstanceKey = Vec<u8>;
pub type ContractInstanceValue = Vec<u8>;
pub type ContractType = i8;
pub type AccessType = i8;
pub type TransactionHash = [u8; 32];
pub type EventData = Vec<u8>;
pub mod arithmetic {
    pub type ScalarLittle = [u8; 16];
    pub type ScalarBig = [u8; 32];
}
