// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

interface IIBPProxy {
    // Proxy functions
    function proposeUpgrade(address newImplementation) external;
    function voteUpgrade(bool support) external returns (uint16 totalWeight);
    function executeUpgrade() external;
    function getImplementation() external view returns (address);
    function getPendingUpgrade() external view returns (address);
    function removeTemplar() external;
}

interface IIBPImplementation {
    // Network management
    function createNetwork() external returns (uint32 networkId);
    function setNetworkDns(uint32 networkId, uint8 orgId, bool enabled) external;
    function addPylon(uint32 networkId, address pylon) external;
    function removePylon(uint32 networkId, address pylon) external;
    
    // Pylon management
    function setPylonOrg(address pylon, uint8 orgId) external returns (uint32 proposalId);
    function setPylonLevel(address pylon, uint8 level) external returns (uint32 proposalId);
    
    // DNS controller management
    function setDnsController(uint8 orgId, address controller) external returns (uint32 proposalId);
    function getDnsController(uint8 orgId) external view returns (address);
    
    // Probe management
    function whitelistProbe(address probe) external returns (uint32 proposalId);
    function revokeProbe(address probe) external returns (uint32 proposalId);
    function isProbeWhitelisted(address probe) external view returns (bool);
    
    // Governance
    function propose(uint8 proposalType) external returns (uint32 proposalId);
    function vote(uint32 proposalId, bool support) external returns (uint16 weight);
    function executeProposal(uint32 proposalId) external;
    
    // Query functions
    function getNetworkInfo(uint32 networkId) external view returns (
        uint8 levelRequirement,
        bool ibpDnsEnabled,
        bool dottersDnsEnabled
    );
    function getNetworkCount() external view returns (uint32);
    function getProposal(uint32 proposalId) external view returns (
        uint8 proposalType,
        address proposer
    );
    function getPylonLevel(address pylon) external view returns (uint8);
    function getPylonStatus(address pylon) external view returns (uint8);
    function getPylonMetrics(address pylon) external view returns (
        uint8 uptime,
        uint16 latency,
        uint32 regions,
        uint32 window,
        uint8 reportCount
    );
    
    // Monitoring
    function reportProbeData(
        address pylon,
        uint32 regions,
        uint16 latency,
        uint8 uptime
    ) external returns (uint32 window);
    function finalizeWindow(address pylon, uint32 window) external returns (uint8 status);
}

// Combined interface for easier interaction
interface IIBP is IIBPProxy, IIBPImplementation {}
