import { EnvironmentsEnum } from '@terradharitri/sdk-dapp/types';

export interface StateType {
  isMenuToggled: boolean;
  dappEnvironment: EnvironmentsEnum;
}

export const initializer: StateType = {
  isMenuToggled: false,
  dappEnvironment: EnvironmentsEnum.mainnet,
};
