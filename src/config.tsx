import { EnvironmentsEnum } from '@terradharitri/sdk-dapp/types';

export const applicationName = 'Utils';
export const companyName = 'Dharitri';
export const companyWebsite = 'https://dharitri.org/';
export const explainerApiUrl = '/xbot/api/xai';

export const ApiBaseUrls = {
  [EnvironmentsEnum.mainnet]: 'https://tools.dharitri.org',
  [EnvironmentsEnum.devnet]: 'https://devnet-tools.dharitri.org',
  [EnvironmentsEnum.testnet]: 'https://testnet-tools.dharitri.org'
};

export const miscApi = 'https://misc-api.dharitri.org';
