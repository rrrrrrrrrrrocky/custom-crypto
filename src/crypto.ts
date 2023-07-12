import * as crypto from "crypto";
import { nanoid } from "nanoid";

const ALGORITHM = "aes-256-cbc";

export const encrypt = (password: string) => {
  const KEY: crypto.CipherKey = crypto
    .randomBytes(32)
    .toString("hex")
    .slice(0, 32);
  const IV: crypto.BinaryLike = crypto
    .randomBytes(16)
    .toString("base64")
    .slice(0, 16);

  const cipher = crypto.createCipheriv(ALGORITHM, KEY, IV);
  let encrypted = cipher.update(password, "utf8", "base64");
  encrypted += cipher.final("base64");
  return { encrypted, key: KEY, iv: IV };
};

/**
 * @example const { encrypted, key, iv } = encrypt('password')
 * @param key encrypt에서 만들어진 KEY값과 동일해야 복호화됨
 * @param iv encrypt에서 만들어진 IV값과 동일해야 복호화됨
 */
export const decrypt = (
  text: string,
  key: crypto.CipherKey,
  iv: crypto.BinaryLike
) => {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  const decrypted = decipher.update(text, "base64", "utf8");
  return decrypted + decipher.final("utf8");
};

export const encryptPassword = (password: string) => {
  const { encrypted, key, iv } = encrypt(password);
  const pwArr = encrypted.split("");
  const uidArr = nanoid().split("");
  const result = new Array(pwArr.length + uidArr.length);

  let pwArrIndex = 0;
  let uidArrIndex = 0;
  let resultIndex = 0;

  while (pwArrIndex < pwArr.length && uidArrIndex < uidArr.length) {
    result[resultIndex++] = pwArr[pwArrIndex++];
    result[resultIndex++] = uidArr[uidArrIndex++];
  }

  while (pwArrIndex < pwArr.length) {
    result[resultIndex++] = pwArr[pwArrIndex++];
  }

  while (uidArrIndex < uidArr.length) {
    result[resultIndex++] = uidArr[uidArrIndex++];
  }

  return { encryptedPassword: result.join(""), key, iv };
};

export const decryptPassword = (
  encryptPassword: string,
  key: crypto.CipherKey,
  iv: crypto.BinaryLike
) => {
  const pwArr = encryptPassword.split("");
  const password = pwArr.filter((_, idx) => Number(idx) % 2 === 0).join("");
  const decryptPw = decrypt(password, key, iv);
  return decryptPw;
};
