import { useCallback } from 'react';
import { MessageComputer } from '@terradharitri/sdk-core';

import { useGetIsLoggedIn } from '@terradharitri/sdk-dapp/hooks';
import { useGetLoginInfo } from '@terradharitri/sdk-dapp/hooks/account/useGetLoginInfo';
import { LoginMethodsEnum } from '@terradharitri/sdk-dapp/types';
import { signMessage } from '@terradharitri/sdk-dapp/utils';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useCallbackRoute } from 'hooks/useCallbackRoute';
import { MESSAGE_KEY, SIGNATURE_KEY, STATUS_KEY } from 'localConstants/storage';
import { useSignMessageSectionContext } from 'pages/SignMessage/context';
import { routeNames } from 'routes';

export const useSignMessageSectionActions = () => {
  const { setSignedMessagePayload, messageToSign } =
    useSignMessageSectionContext();

  const { search } = useLocation();
  const { loginMethod } = useGetLoginInfo();
  const isLoggedIn = useGetIsLoggedIn();
  const navigate = useNavigate();
  const callbackRoute = useCallbackRoute();

  const [searchParams] = useSearchParams();

  const handleSignMessage = useCallback(async () => {
    searchParams.delete(SIGNATURE_KEY);
    searchParams.delete(STATUS_KEY);
    const messageComputer = new MessageComputer();

    if (!isLoggedIn) {
      const route = search
        ? `${routeNames.unlock}${search}&callbackUrl=${callbackRoute}`
        : `${routeNames.unlock}?callbackUrl=${callbackRoute}`;
      const isWallet = loginMethod === LoginMethodsEnum.wallet;

      navigate(
        isWallet
          ? encodeURIComponent(route)
          : `${route}?${MESSAGE_KEY}=${messageToSign}`,
      );
      return;
    }

    const message = await signMessage({
      message: messageToSign,
      callbackRoute: `${routeNames.signMessage}${search}`,
    });

    if (!message) {
      return;
    }

    const packedMessage = messageComputer.packMessage(message);

    setSignedMessagePayload(JSON.stringify(packedMessage, null, 2));
  }, [
    callbackRoute,
    isLoggedIn,
    loginMethod,
    messageToSign,
    navigate,
    search,
    setSignedMessagePayload,
  ]);

  return {
    handleSignMessage,
  };
};
