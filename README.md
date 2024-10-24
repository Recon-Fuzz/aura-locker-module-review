![Recon Balancer Review Image](https://media.publit.io/file/Audit-Review-3.png)

# Recon Security Review

## Introduction
Alex The Entreprenerd performed a 1 day review of Aura Locker V2 for Balancer DAO.

Repo:
https://github.com/onchainification/aura_locker_v2

Commit Hash:
`07294ae3638909ecd768a6a0f831fa513abe91a0`

This review uses [Code4rena Severity Classification](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization)

The Review is done as a best effort service, while a lot of time and attention was dedicated to the security review, it cannot guarantee that there are no bugs remaining in the contracts in scope.

As a general rule we always recommend doing one additional security review until no bugs are found, this in conjunction with a Guarded Launch and a Bug Bounty can help further reduce the likelihood that high impact bugs are missed.

## About Recon

Recon offers boutique security reviews, invariant testing development and is pioneering Cloud Fuzzing as a best practice by offering Recon Pro, the most complete tool to run tools such as Echidna, Medusa, Foundry, Kontrol and Halmos in the cloud with just a few clicks.

## About Alex

[Alex](https://x.com/gallodasballo) is a well known Security Researcher that has collaborated with multiple contest firms such as:
- Code4rena - One of the most prolific and respected judges, won the Tapioca contest, at the time the 3rd highest contest pot ever
- Spearbit - Have done reviews for Tapioca, Threshold USD, Velodrome and more
- Recon - Centrifuge Invariant Testing Suite, Corn, Badger and Liquity invariants as well as live monitoring



## Table of Contents

- **Executive Summary**
- **QA**
  - Q-01 Operative Gotcha - Safe.getModules is limited to the first 10 modules
- **Info**
  - I-01 Nitpick: `SAFE` and `BALANCER_MULTISIG` are the same value and are used inconsistently
  - I-02 Address Checks
- **Gas**
  - G-01 GAS: Can skip check to save 200 gas


# Executive Summary

A summary of the core findings from this review:
- The module allows a registered chainlink upkeep to automatically re-lock aura locks
- Funds cannot be stolen in any way
- Due to the lax timing and lack of MEV, I cannot expect the upkeep to cause any particular issue
- It's worth noting that in case there is a desire to deprecate the module, for example to stop re-locking, it will be sufficient to remove it from the safe modules
- There is no particular risk tied to adding this module as in the worst case it will consume a bit of `LINK` token to perform the upkeep

# Q-01 Operative Gotcha - Safe.getModules is limited to the first 10 modules

## Impact

`_isModuleEnabled` is written as follows:

https://github.com/onchainification/aura_locker_v2/blob/07294ae3638909ecd768a6a0f831fa513abe91a0/src/AuraLockerModule.sol#L123

```solidity
    /// @dev The Gnosis Safe v1.1.1 does not yet have the `isModuleEnabled` method, so we need a workaround
    function _isModuleEnabled() internal view returns (bool) {
        address[] memory modules = SAFE.getModules();
        for (uint256 i = 0; i < modules.length; i++) {
            if (modules[i] == address(this)) return true;
        }
        return false;
    }
```

Which uses `getModules`, which is paginated and limited to returning the first 10 enabled modules

https://etherscan.io/address/0x34cfac646f301356faa8b21e94227e3583fe3f5f#code
```solidity
    function getModules()
        public
        view
        returns (address[] memory)
    {
        (address[] memory array,) = getModulesPaginated(SENTINEL_MODULES, 10);
        return array;
    }
```

It's worth noting that if this module were to be used in a setup with multiple other modules, the check could fail. However, currently there are no other modules set, meaning that the code is safe as is.

Additionally, even if the check were to fail, no particular damage would be caused to the Safe, at worst the `checkUpkeep` would always return false, making no upkeep run, but causing no DOS to the Safe.

## Mitigation

Add a comment to the `_isModuleEnabled` to indicate that it will only work with a max of 10 others and ensure that on setup, the Safe being integrated with has less than 10 modules. 

# I-01 Nitpick: `SAFE` and `BALANCER_MULTISIG` are the same value and are used inconsistently

## Impact

The casting of `address(SAFE))` is unnecessary if you use [`BALANCER_MULTISIG`]:(https://github.com/onchainification/aura_locker_v2/blob/07294ae3638909ecd768a6a0f831fa513abe91a0/src/AuraLockerModule.sol#L20-L21)

```solidity
    address public constant BALANCER_MULTISIG = 0x10A19e7eE7d7F8a52822f6817de8ea18204F2e4f;
    IGnosisSafe public constant SAFE = IGnosisSafe(payable(BALANCER_MULTISIG));
```

As is done in [`onlyGovernance`]:(https://github.com/onchainification/aura_locker_v2/blob/07294ae3638909ecd768a6a0f831fa513abe91a0/src/AuraLockerModule.sol#L67C1-L71C6)

```solidity
    /// @notice Enforce that the function is called by governance only
    modifier onlyGovernance() {
        if (msg.sender != BALANCER_MULTISIG) revert NotGovernance(msg.sender);
        _;
    }
```

## Mitigation

`onlyGovernance` could alternatively be changed to use `address(SAFE)` and make the code consistent.

This has no impact on the bytecode and is therefore only for consistency purposes.

# I-02 Address Checks

The addresses are correctly set

```solidity
address public constant BALANCER_MULTISIG = 0x10A19e7eE7d7F8a52822f6817de8ea18204F2e4f
```
[Confirmed, 6/11 multi](https://etherscan.io/address/0x10A19e7eE7d7F8a52822f6817de8ea18204F2e4f#code)

```solidity
IERC20 public constant AURA = IERC20(0xC0c293ce456fF0ED870ADd98a0828Dd4d2903DBF); // OK
```
[src](https://etherscan.io/address/0xC0c293ce456fF0ED870ADd98a0828Dd4d2903DBF#code)

```solidity
ILockAura public constant AURA_LOCKER = ILockAura(0x3Fa73f1E5d8A792C80F426fc8F84FBF7Ce9bBCAC); // OK
```
[src](https://etherscan.io/address/0x3Fa73f1E5d8A792C80F426fc8F84FBF7Ce9bBCAC#code)

# G-01 GAS: Can skip check to save 200 gas

## Impact

[`performUpkeep`](https://github.com/onchainification/aura_locker_v2/blob/07294ae3638909ecd768a6a0f831fa513abe91a0/src/AuraLockerModule.sol#L112-L113) has a check to verify if there's any re-lockable balance:

```solidity
    /// @notice The actual execution of the action determined by the `checkUpkeep` method (AURA locking)
    function performUpkeep(bytes calldata /* _performData */ ) external override onlyKeeper {
        if (!_isModuleEnabled()) revert ModuleNotEnabled();

        (, uint256 unlockable,,) = AURA_LOCKER.lockedBalances(address(SAFE));
        if (unlockable == 0) revert NothingToLock(block.timestamp);
```

If the check fails, the call will revert.

However, [vlAURA](https://etherscan.io/address/0x3Fa73f1E5d8A792C80F426fc8F84FBF7Ce9bBCAC#code) already has this check:

```solidity
    function _processExpiredLocks(
        address _account,
        bool _relock,
        address _rewardAddress,
        uint256 _checkDelay
    ) internal updateReward(_account) {
/// OMITTED

require(length > 0, "no locks"); /// @audit Reverts here
```

Meaning the call can be skipped to save around 200 gas.

## Mitigation

Consider removing the check to save 200 gas

# Additional Security Services Offered By Recon

- Ongoing security consulting and invariant testing - Recon Legendary
- Cloud Fuzzing as a Service - The easiest way to run invariant tests in the cloud (Recon Pro)
  - Includes continous live monitoring where invariant tests are run against a forked chain state
  - Includes governance fuzzing to invariant test system changes against governance proposals
- Security Reviews by [Alex The Entreprenerd](https://x.com/gallodasballo) and the [Recon Team](https://getrecon.xyz/#team)
