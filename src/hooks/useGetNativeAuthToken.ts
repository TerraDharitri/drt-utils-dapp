import { useGetLoginInfo } from '@terradharitri/sdk-dapp/hooks/account/useGetLoginInfo';

export const useGetNativeAuthToken = () => {
  const { tokenLogin } = useGetLoginInfo();
  return tokenLogin?.nativeAuthToken;
};
