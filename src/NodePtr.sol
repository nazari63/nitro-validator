// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

type NodePtr is uint256;

library LibNodePtr {
    using LibNodePtr for NodePtr;

    // First byte index of the header
    function header(NodePtr self) internal pure returns (uint256) {
        return uint80(NodePtr.unwrap(self));
    }

    // First byte index of the content
    function content(NodePtr self) internal pure returns (uint256) {
        return uint80(NodePtr.unwrap(self) >> 80);
    }

    // Content length
    function length(NodePtr self) internal pure returns (uint256) {
        return uint80(NodePtr.unwrap(self) >> 160);
    }

    // Total length (header length + content length)
    function totalLength(NodePtr self) internal pure returns (uint256) {
        return self.length() + self.content() - self.header();
    }

    // Pack 3 uint80s into a uint256
    function toNodePtr(uint256 _header, uint256 _content, uint256 _length) internal pure returns (NodePtr) {
        return NodePtr.wrap(_header | _content << 80 | _length << 160);
    }
}
