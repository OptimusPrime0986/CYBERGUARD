import React from "react";
const I = ({ children, size = 18 }) => <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>;
export const Logo = () => (<svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2.5 4.5 7v8.2c0 7.1 4.7 12.3 11.5 14.3 6.8-2 11.5-7.2 11.5-14.3V7L16 2.5Z" fill="#0b6e80" /><path d="m10.6 16.4 3.8 3.8 7-7.6" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>);
export const IconGrid = () => <I><rect x="3.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.5" /></I>;
export const IconChecks = () => <I><path d="m4 7 2 2 3.5-4" /><path d="m4 17 2 2 3.5-4" /><path d="M13 7h7M13 17h7" /></I>;
export const IconUsers = () => <I><circle cx="9" cy="8" r="3.2" /><path d="M3 19c.6-3.2 3-5 6-5s5.4 1.8 6 5" /><path d="M16.5 5.2a3 3 0 0 1 0 5.6M18 14.3c1.7.6 2.7 2 3 4.7" /></I>;
export const IconUser = () => <I><circle cx="12" cy="8" r="3.6" /><path d="M4.5 20c.8-3.8 3.8-6 7.5-6s6.7 2.2 7.5 6" /></I>;
export const IconOut = () => <I><path d="M10 4H5.5A1.5 1.5 0 0 0 4 5.5v13A1.5 1.5 0 0 0 5.5 20H10" /><path d="m15 8 4 4-4 4M19 12H9" /></I>;
export const IconBack = () => <I size={16}><path d="m15 5-7 7 7 7" /></I>;
