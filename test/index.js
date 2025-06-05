import "should";
import b2k from "../index.js";

describe("test", function () {
  it("Personal version", async function () {
    const args = {
      otp: ["otp"],
      password: "test",
      source: `${import.meta.dirname}/vault.bcup`,
    };
    const vault = await b2k.open_vault(args);
    const records = b2k.concert_to_records(args, vault);
    records.should.eql([
      {
        Group: "/Group A",
        Title: "Entry A",
        Username: "username_a",
        Password: "entry_a",
        URL: undefined,
        Notes: "# text\n\nhttp://entry.a/\n\n# note\n\nAbout entry A",
        TOTP: undefined,
      },
    ]);
  });
});
