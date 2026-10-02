//! Built-in cluster profiles. Values are public: observable on-chain or published in the Z.ink docs.

pub struct Cluster {
    pub name: &'static str,
    pub genesis_hash: &'static str,
    pub default_rpc: &'static str,
    pub explorer_tx: &'static str,
    /// Programs any key may call at the top level, as (label, address).
    pub programs: &'static [(&'static str, &'static str)],
}

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

pub const ZINK_TESTNET: Cluster = Cluster {
    name: "zink-testnet",
    genesis_hash: "6qaAozzun2WV83PRDgqf79WXtbqfnezKB3demjxXV5EY",
    default_rpc: "https://rpc1.z.ink",
    explorer_tx: "https://explorer.z.ink/tx/",
    programs: &[
        ("sage", "C4SAgeKLgb3pTLWhVr6NRwWyYFuTR7ZeSXFrzoLwfMzF"),
        (
            "player-profile",
            "C4PRoFNroxxzdgeCoM31LJjYRg7kT6ymogSTAT99iD1u",
        ),
        (
            "profile-faction",
            "C4FACQA1PpNRKrjQ2862ABNR42DTz7EzGj1uhTNFASwP",
        ),
        (
            "compute-budget",
            "ComputeBudget111111111111111111111111111111",
        ),
        ("spl-token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        (
            "associated-token",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        ),
        ("system", SYSTEM_PROGRAM),
    ],
};

/// Mainnet is deliberately absent until the permission-bit mapping is done.
pub fn by_name(name: &str) -> Option<&'static Cluster> {
    std::iter::once(&ZINK_TESTNET).find(|c| c.name == name)
}
