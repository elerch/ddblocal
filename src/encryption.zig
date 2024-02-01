const std = @import("std");

const pbkdf2_iterations = 1000000; // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
pub const salt_length = 256 / 8; // https://crypto.stackexchange.com/a/56132
pub const encoded_salt_length = std.base64.standard.Encoder.calcSize(salt_length);
pub const key_length = std.crypto.aead.salsa_poly.XSalsa20Poly1305.key_length;
pub const encoded_key_length = std.base64.standard.Encoder.calcSize(key_length);

/// Generates a random salt of appropriate length
pub fn randomSalt(salt: *[salt_length]u8) void {
    std.crypto.random.bytes(salt);
}

/// Generates a random salt of appropriate length, encoded into ASCII
pub fn randomEncodedSalt(encoded_salt: *[encoded_salt_length]u8) void {
    var salt: [salt_length]u8 = undefined;
    randomSalt(salt[0..]);
    _ = std.base64.standard.Encoder.encode(encoded_salt, salt[0..]);
}

/// Generates a random key of appropriate length
pub fn randomKey(key: *[key_length]u8) void {
    std.crypto.random.bytes(key);
}

/// Generates a random key of appropriate length, encoded into ASCII
pub fn randomEncodedKey(encoded_key: *[encoded_key_length]u8) void {
    var key: [key_length]u8 = undefined;
    randomKey(key[0..]);
    _ = std.base64.standard.Encoder.encode(encoded_key, key[0..]);
}

/// Decodes key from encoded version
pub fn decodeKey(key: *[key_length]u8, encoded_key: [encoded_key_length]u8) !void {
    try std.base64.standard.Decoder.decode(key, encoded_key[0..]);
}

// Derives key bytes given a plain text password and salt. It is recommended
// to use randomSalt to generate a salt - for storage, recommend a suitable ASCII encoding
pub fn deriveKey(derived_key: *[key_length]u8, password: []const u8, salt: []const u8) !void {
    // Derive key using PBKDF2
    try std.crypto.pwhash.pbkdf2(derived_key[0..], password, salt, pbkdf2_iterations, std.crypto.auth.hmac.sha2.HmacSha256);
}

// Derives key bytes given a plain text password and ascii encoded salt.
// Enables encryption with a single line of code, e.g.
// data = try encrypt(allocator, try deriveKeyFromEncodedSalt(password, salt), message);
//
// and decryption with:
//
// message = try decrypt(allocator, try deriveKeyFromEncodedSalt(password, salt) data);
pub fn deriveKeyFromEncodedSalt(derived_key: *[key_length]u8, password: []const u8, encoded_salt: []const u8) ![key_length]u8 {
    var salt: [salt_length]u8 = undefined;
    try std.base64.standard.Decoder.decode(&salt, encoded_salt);
    try deriveKey(derived_key, password, salt[0..]);
    return derived_key.*;
}

/// Encrypts data. Use deriveKey function to get a key from password/salt
/// Caller owns memory
pub fn encrypt(allocator: std.mem.Allocator, key: [key_length]u8, plaintext: []const u8) ![]const u8 {
    var ciphertext = try allocator.alloc(
        u8,
        std.crypto.aead.salsa_poly.XSalsa20Poly1305.nonce_length + std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length + plaintext.len,
    );
    errdefer allocator.free(ciphertext);

    // Create the nonce
    const nonce_length = std.crypto.aead.salsa_poly.XSalsa20Poly1305.nonce_length;
    std.crypto.random.bytes(ciphertext[0..nonce_length]); // add nonce to beginning of our ciphertext
    const nonce = ciphertext[0..nonce_length];
    const tag = ciphertext[nonce_length .. nonce_length + std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length];
    const c = ciphertext[nonce_length + std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length ..];

    // Do the encryption
    std.crypto.aead.salsa_poly.XSalsa20Poly1305.encrypt(
        c,
        tag,
        plaintext,
        "ad",
        nonce.*,
        key,
    );
    return ciphertext;
}

/// Encrypts data. Use deriveKey function to get a key from password/salt
/// Caller owns memory
pub fn encryptAndEncode(allocator: std.mem.Allocator, key: [key_length]u8, plaintext: []const u8) ![]const u8 {
    const ciphertext = try encrypt(allocator, key, plaintext);
    defer allocator.free(ciphertext);
    const Encoder = std.base64.standard.Encoder;
    var encoded_ciphertext = try allocator.alloc(u8, Encoder.calcSize(ciphertext.len));
    errdefer allocator.free(encoded_ciphertext);
    return Encoder.encode(encoded_ciphertext, ciphertext);
}

/// Decrypts data. Use deriveKey function to get a key from password/salt
pub fn decrypt(allocator: std.mem.Allocator, key: [key_length]u8, ciphertext: []const u8) ![]const u8 {
    var plaintext = try allocator.alloc(
        u8,
        ciphertext.len - std.crypto.aead.salsa_poly.XSalsa20Poly1305.nonce_length - std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length,
    );
    errdefer allocator.free(plaintext);
    const nonce_length = std.crypto.aead.salsa_poly.XSalsa20Poly1305.nonce_length;
    const nonce = ciphertext[0..nonce_length].*;
    const tag = ciphertext[nonce_length .. nonce_length + std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length].*;
    const c = ciphertext[nonce_length + std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length ..];

    try std.crypto.aead.salsa_poly.XSalsa20Poly1305.decrypt(
        plaintext,
        c,
        tag,
        "ad",
        nonce,
        key,
    );
    return plaintext;
}

/// Decrypts encoded data. Does the reverse of encryptAndEncode
/// Caller owns memory
pub fn decodeAndDecrypt(allocator: std.mem.Allocator, key: [key_length]u8, encoded_ciphertext: []const u8) ![]const u8 {
    const Decoder = std.base64.standard.Decoder;
    const ciphertext_len = try Decoder.calcSizeForSlice(encoded_ciphertext);
    var ciphertext = try allocator.alloc(u8, ciphertext_len);
    defer allocator.free(ciphertext);
    try std.base64.standard.Decoder.decode(ciphertext, encoded_ciphertext);
    return try decrypt(allocator, key, ciphertext);
}

// This is a pretty long running test...
// test "can encrypt and decrypt data with simpler api" {
//     const allocator = std.testing.allocator;
//     const plaintext = "Hello, Zig!";
//     const password = "mySecurePassword";
//     var key: [key_length]u8 = undefined;
//     var salt: [encoded_salt_length]u8 = undefined;
//     randomEncodedSalt(salt[0..]);
//
//     const ciphertext = try encrypt(allocator, try deriveKeyFromEncodedSalt(&key, password, salt[0..]), plaintext);
//     defer allocator.free(ciphertext);
//     std.log.debug("Ciphertext: {s}\n", .{std.fmt.fmtSliceHexLower(ciphertext)});
//     const decrypted_text = try decrypt(allocator, key, ciphertext);
//     defer allocator.free(decrypted_text);
//     try std.testing.expectEqualStrings(plaintext, decrypted_text[0..]);
// }

test "can encrypt and decrypt data with simpler api but without KDF" {
    const allocator = std.testing.allocator;
    const plaintext = "Hello, Zig!";
    var key: [key_length]u8 = undefined;
    var encoded_key: [encoded_key_length]u8 = undefined;
    randomEncodedKey(encoded_key[0..]);
    // std.testing.log_level = .debug;
    std.log.debug("Encoded key: {s}", .{encoded_key});

    try decodeKey(&key, encoded_key);
    const ciphertext = try encrypt(allocator, key, plaintext);
    defer allocator.free(ciphertext);
    std.log.debug("Ciphertext: {s}\n", .{std.fmt.fmtSliceHexLower(ciphertext)});
    const decrypted_text = try decrypt(allocator, key, ciphertext);
    defer allocator.free(decrypted_text);
    try std.testing.expectEqualStrings(plaintext, decrypted_text[0..]);
}

// test "can encrypt and decrypt data" {
//     var tag: [std.crypto.aead.salsa_poly.XSalsa20Poly1305.tag_length]u8 = undefined;
//     const password = "mySecurePassword";
//
//     var salt: [salt_length]u8 = undefined;
//     randomSalt(salt[0..]);
//
//     // Derive key using PBKDF2
//     var derived_key: [std.crypto.aead.salsa_poly.XSalsa20Poly1305.key_length]u8 = undefined;
//     try std.crypto.pwhash.pbkdf2(&derived_key, password, &salt, pbkdf2_iterations, std.crypto.auth.hmac.sha2.HmacSha256);
//
//     var nonce: [std.crypto.aead.salsa_poly.XSalsa20Poly1305.nonce_length]u8 = undefined;
//     std.crypto.random.bytes(&nonce);
//
//     const plaintext = "Hello, Zig!";
//     var ciphertext = [_]u8{0} ** plaintext.len;
//     std.crypto.aead.salsa_poly.XSalsa20Poly1305.encrypt(ciphertext[0..], &tag, plaintext, "", nonce, derived_key);
//     var decrypted_text = [_]u8{0} ** ciphertext.len;
//     try std.crypto.aead.salsa_poly.XSalsa20Poly1305.decrypt(&decrypted_text, ciphertext[0..], tag, "", nonce, derived_key);
//
//     std.log.debug("Ciphertext: {s}\n", .{std.fmt.fmtSliceHexLower(&ciphertext)});
//
//     try std.testing.expectEqualStrings(plaintext, decrypted_text[0..]);
// }
