# Runtime 482 selective-metagraph API review

The public finalized Snow RPC observation at block 9,341,171, hash
`0x4f9b6a9d9f9b5e598d912387872c8c943892bf3638cd4c59aa9d9b49c0ee41f0`,
reports `node-subtensor/482/1/1` and the same 25 API version pairs as 481.
The exact captured metadata is 367,676 bytes, SHA256
`937fc71c0783462556cc26fab9da9d771e0c96b657b1cd749fb0d4e4b28d9281`,
BLAKE2b-256 `512a7c0c9d87763428a4c927670f7a01f014ab9b1166d0709cfb08cef280be43`.
Captured code is 2,665,898 bytes, SHA256
`4fd14869c13661c0ea29738a4bdf9181b9a3d7a7149b99c83f4a04e77bcef356`.

Official source tag [v482](https://github.com/RaoFoundation/subtensor/releases/tag/v482)
is commit `8cf229f8ef969389d054a4c161b53ffd164a041f`, tree
`4cfd29d8d12499775e2b1cbabf64e6fa41f1f7cf`. Compared with reviewed481
`6a972693ae9580541225bd37696ac2fee26b8ae9`, selective-metagraph's declaration,
delegate and complete 77-field source layout are unchanged. The existing211-path
source manifest has 38 changed paths; that comparison is not an exhaustive
source qualification.

The API3 exception now admits exactly 481/1/1 and 482/1/1 for node-subtensor.
API2 behavior is unchanged. A deterministic test using the captured482 version
reply reproduced the previous production refusal, then passed after this change.
Tests retain rejection of other names, future specs and transaction/state
versions. Captured482 metadata passes provisional and all seven fleet consumed
interface purposes; selected479/481 API and metadata regressions also pass.
Tests ran in Docker with Go1.27.3 linux/arm64, count1, readonly sources and
separate caches. This is focused interface evidence, not full release qualification.

This change adds no reviewed-native-owner source capability, runtime artifact
authority, economic equivalence, successor opt-in, deployment or signing approval.
Runtime482 also changes miner payout allocation, Null-epoch scheduling, coldkey
swap reservations, proxy handling and new-subnet emission defaults. Those
changes still require broader review, captured-Wasm execution and the applicable
source-bound rehearsals before operational approval.
