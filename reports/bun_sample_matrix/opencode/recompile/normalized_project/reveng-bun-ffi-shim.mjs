const unsupported = (api) => (...args) => {
  throw new Error(
    `${api} from bun:ffi is not supported in the Node rebuild. This code path requires manual porting or a Bun runtime.`
  );
};
export const dlopen = unsupported("dlopen");
export const ptr = unsupported("ptr");
export const FFIType = new Proxy(Object.create(null), {
  get(_target, prop) {
    return String(prop);
  },
});
export default {
  dlopen,
  ptr,
  FFIType,
};
