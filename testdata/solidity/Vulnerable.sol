// SPDX-License-Identifier: MIT
// Solidity testdata: intentionally vulnerable patterns for scanner testing.
pragma solidity ^0.8.0;

contract Vulnerable {

    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // CWE-841: Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // VULNERABLE: state update after external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // should be BEFORE the call
    }

    // SWC-115: Authorization via tx.origin (phishing attack vector)
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Not authorized"); // use msg.sender instead
        owner = newOwner;
    }

    // SWC-101: Integer overflow (pre-0.8.x style — kept for scanner testing)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // in 0.8+ this reverts on overflow, but pattern still flagged
    }

    // SWC-104: Unchecked call return value
    function sendEther(address payable recipient) public {
        recipient.send(1 ether); // return value not checked
    }

    // Hardcoded address (bad practice)
    address constant HARDCODED = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
