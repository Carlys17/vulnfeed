// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Intentionally vulnerable fixture for testing VulnFeed detection.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    // Reentrancy: sends Ether before updating state.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // Unchecked external call used before state update (same class).
    function donate(address to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "failed");
        balances[to] += amount;
    }

    receive() external payable {}
}
