export interface OIDCUserInfo {
  sub: string;
  [claim: string]: unknown;
}
