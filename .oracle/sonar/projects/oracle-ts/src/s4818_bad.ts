// S4818 bad: raw datagram socket module in use.
const dgram = require("dgram");
const channel = dgram.createSocket("udp4");
module.exports = { channel };
