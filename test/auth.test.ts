import * as auth from "../src/controllers/auth"

//TODO add more

it("", async () => {
    expect.assertions(1);
    const generatedJWT = auth.generateAccessToken("redbluegreen")
    const verifyJWT = auth.verifyAccessToken(generatedJWT);
    expect(verifyJWT).toBe("redbluegreen");   
})