import {
  Address,
  Message,
  MessageComputer,
} from '@terradharitri/sdk-core';
import * as ed from '@noble/ed25519';

export const verifySignature = async (
  address: string,
  messageString: string,
  signature: Uint8Array,
): Promise<boolean> => {
  try {
    const bech32Address = Address.fromBech32(address);

    const message = new Message({
      address: bech32Address,
      data: Buffer.from(messageString, 'utf8'),
    });

    const messageComputer = new MessageComputer();
    const messageBytes = messageComputer.computeBytesForVerifying(message);

    // Convert bech32 address to public key
    const pubKeyHex = bech32Address.pubkey().toString('hex');

    return await ed.verify(signature, messageBytes, pubKeyHex);
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
};

