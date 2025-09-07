// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

interface IIBPProxy {
    // Events
    event UpgradeProposed(address indexed proposer, address indexed newImplementation, uint256 timestamp);
    event UpgradeVoted(address indexed voter, bool support, uint16 weight);
    event UpgradeExecuted(address indexed oldImplementation, address indexed newImplementation);
    event TemplarRemoved(address indexed templar);
    
    // Proxy functions
    function proposeUpgrade(address newImplementation) external;
    function voteUpgrade(bool support) external returns (uint16 totalWeight);
    function executeUpgrade() external;
    function getImplementation() external view returns (address);
    function getPendingUpgrade() external view returns (address);
    function removeTemplar() external;
}

interface IIBPImplementation {
    // Events
    event NetworkCreated(uint32 indexed networkId, address indexed creator, uint8 levelRequirement);
    event NetworkDnsUpdated(uint32 indexed networkId, uint8 indexed orgId, bool enabled);
    event PylonAdded(uint32 indexed networkId, address indexed pylon);
    event ProposalCreated(uint32 indexed proposalId, address indexed proposer, uint8 proposalType);
    event ProposalVoted(uint32 indexed proposalId, address indexed voter, bool support, uint16 weight);
    event ProposalExecuted(uint32 indexed proposalId, address indexed executor);
    event PylonLevelChanged(address indexed pylon, uint8 oldLevel, uint8 newLevel);
    event PylonOrgChanged(address indexed pylon, uint8 orgId);
    event DnsControllerChanged(uint8 indexed orgId, address indexed controller);
    event ProbeWhitelisted(address indexed probe);
    event ProbeRevoked(address indexed probe);
    event ProbeDataReported(address indexed pylon, address indexed probe, uint32 window, bytes32 reportHash, uint8 statusCode);
    event WindowFinalized(address indexed pylon, uint32 indexed window, uint8 status, uint8 totalCount);
    
    // Bootstrap
    function bootstrap() external;
    
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
        uint8 status,
        uint16 avgLatency,
        uint8 totalCount,
        uint8 healthyCount,
        uint32 window
    );
    
    // Monitoring
    function reportProbeData(
        address pylon,
        bytes32 reportHash,
        uint8 statusCode
    ) external returns (uint32 window);
    function finalizeWindow(address pylon, uint32 window) external returns (uint8 status);
}

// Combined interface for easier interaction
interface IIBP is IIBPProxy, IIBPImplementation {}
