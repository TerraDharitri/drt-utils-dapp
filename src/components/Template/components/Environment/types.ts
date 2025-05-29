import type { EnvironmentsEnum } from '@terradharitri/sdk-dapp/types';

export interface EnvironmentPropsType {
  chain: EnvironmentsEnum;
}

export interface OptionType {
  value: EnvironmentsEnum;
  label: EnvironmentsEnum;
}
