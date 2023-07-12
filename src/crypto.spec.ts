import { encrypt } from "./crypto";

describe("encrypt", () => {
  const formatter = encrypt("text");
  it("iv 문자열 길이가 16이다.", () => {
    expect(formatter.iv.length).toBe(16);
  });
});
