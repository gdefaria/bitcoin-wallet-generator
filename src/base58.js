const Base58 = require('bs58')
const { createHash } = require('crypto')

function checksum(buff) {
	const digest1 = createHash('sha256')
	.update(buff)
	.digest()

	const digest2 = createHash('sha256')
	.update(digest1)
	.digest()

	return Uint8Array.from(digest2.subarray(0, 4))
}

function base58check(hex) {
	if (hex.length % 2 === 1)
		// Length must be even to have a integer
		// amount of bytes, avoiding padding issues
		throw Error(`hex length is odd.`)

	const hexBuffer = Buffer.from(hex, 'hex')
	const finalHex = Buffer.concat([hexBuffer, checksum(hexBuffer)])

	return Base58.encode(finalHex)
}

function fromBase58check(b58) {
	const dataWithChecksum = Base58.decode(b58)
	const data = dataWithChecksum.slice(0, -4)
	const check = dataWithChecksum.slice(-4)

	const expectedChecksum = checksum(data)
	if (check.toString() !== expectedChecksum.toString())
		throw Error('Checksum mismatched')

	return Buffer.from(data).toString('hex')
}

module.exports = {
	base58check,
	fromBase58check,
}