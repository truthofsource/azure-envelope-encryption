// Public type-only contract for the actual bank-details encryption excerpt.
export type Stage2BankDetails = {bankName:string;accountHolder:string;accountType:"checking"|"savings";routingNumber:string;accountNumber:string};
