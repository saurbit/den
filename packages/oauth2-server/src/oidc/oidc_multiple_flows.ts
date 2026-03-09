// TODO: multiple flows for OpenID Connect.
// It basically have a list of flows and
// a method "token()" that will check the grant type
// and call the appropriate flow's token method.
// The refresh token handler will be tried for all flows,
// and if one of them can handle it, it will be used.
// The token verification will also be tried for all flows,
// and if one of them can handle it, it will be used.
// So the order of the flows is important,
// and the first one that can handle the request will be used.
// A method for the openid configuration endpoint will also be needed,
// which will return the supported flows and their configuration.
