// hsd's ecosystem deps are untyped CommonJS. Declaring them as `any`
// keeps the plugin compatible with npm's mirror packages (bns, blru,
// bufio) without shipping our own @types.
declare module 'bns';
declare module 'blru';
declare module 'bufio';
