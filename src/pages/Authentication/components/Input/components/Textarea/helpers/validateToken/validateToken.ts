import { NativeAuthServer } from '@terradharitri/sdk-native-auth-server';

import type { NativeAuthServerConfig } from '@terradharitri/sdk-native-auth-server/lib/src/entities/native.auth.server.config';

export const validateToken = async (
  token: string,
  config: NativeAuthServerConfig,
) => {
  try {
    const server = new NativeAuthServer(config);
    const valid = await server.validate(token);

    return valid;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(error.message);
    }
  }
};
