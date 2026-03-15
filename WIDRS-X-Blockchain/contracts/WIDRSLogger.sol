// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WIDRSLogger {

    struct AttackLog {
        bytes32 hash;
        string attackType;
        string mac;
        uint256 timestamp;
        address reporter;
    }

    AttackLog[] public logs;

    event AttackLogged(
        bytes32 hash,
        string attackType,
        string mac,
        uint256 timestamp,
        address reporter
    );

    function logAttack(
        bytes32 hash,
        string memory attackType,
        string memory mac
    ) public {

        AttackLog memory newLog = AttackLog({
            hash: hash,
            attackType: attackType,
            mac: mac,
            timestamp: block.timestamp,
            reporter: msg.sender
        });

        logs.push(newLog);

        emit AttackLogged(
            hash,
            attackType,
            mac,
            block.timestamp,
            msg.sender
        );
    }

    function getLog(uint256 index) public view returns (
        bytes32,
        string memory,
        string memory,
        uint256,
        address
    ) {
        AttackLog memory log = logs[index];
        return (
            log.hash,
            log.attackType,
            log.mac,
            log.timestamp,
            log.reporter
        );
    }

    function totalLogs() public view returns (uint256) {
        return logs.length;
    }
}
