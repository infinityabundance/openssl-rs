<!-- refinement-level: L4-abi-contract -->
# Control: a justified exemption

The release boundary hands `OwnedBuf` to the C caller exactly once.  Naming the
owner type is unavoidable here because the contract fixes the release site; the
exemption records the review that accepted it.
