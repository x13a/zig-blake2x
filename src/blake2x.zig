const std = @import("std");
const mem = std.mem;

pub const output_len_unknown = 0;

pub const Blake2Xb = struct {
    const Self = @This();
    const Blake2 = std.crypto.hash.blake2.Blake2b512;
    const magic_unknown_output_len = (1 << 32) - 1;
    const max_output_len = (1 << 32) * 64;
    const iv = [8]u64{
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    };
    pub const Options = Blake2.Options;

    b2: Blake2,
    len: usize,
    rem: usize,
    cfg: [Blake2.digest_length]u8,
    h0: [Blake2.digest_length]u8,
    buffer: [Blake2.digest_length]u8,
    offset: usize,
    node_offset: u32,
    read_mode: bool,

    pub fn init(size: usize, options: Options) Self {
        std.debug.assert(size != magic_unknown_output_len);
        std.debug.assert(size < 0xffff_ffff);
        if (options.key) |v| {
            std.debug.assert(v.len <= Blake2.key_length_max);
        }

        var len = size;
        if (len == output_len_unknown) {
            len = magic_unknown_output_len;
        }

        var self: Self = undefined;
        self.b2 = Blake2.init(options);
        self.b2.h[1] ^= @as(u64, len) << 32;
        self.len = len;

        self.rem = len;
        if (self.rem == magic_unknown_output_len) {
            self.rem = max_output_len;
        }

        mem.set(u8, &self.cfg, 0);
        self.cfg[0] = Blake2.digest_length;
        mem.writeIntLittle(u32, self.cfg[4..8], Blake2.digest_length);
        mem.writeIntLittle(u32, self.cfg[12..16], @intCast(u32, self.len));
        self.cfg[17] = Blake2.digest_length;
        if (options.salt) |v| {
            mem.copy(u8, self.cfg[32..], &v);
        }
        if (options.context) |v| {
            mem.copy(u8, self.cfg[48..], &v);
        }

        self.offset = 0;
        self.node_offset = 0;
        self.read_mode = false;

        return self;
    }

    pub fn update(self: *Self, data: []const u8) void {
        if (self.read_mode) {
            std.debug.panic("blake2xb: write after read", .{});
        }
        self.b2.update(data);
    }

    pub fn read(self: *Self, out: []u8) usize {
        if (!self.read_mode) {
            self.b2.final(&self.h0);
            self.read_mode = true;
        }

        if (self.rem == 0) {
            return 0;
        }

        var out_slice = out;
        var n = out_slice.len;
        if (n > self.rem) {
            n = self.rem;
            out_slice = out_slice[0..n];
        }

        if (self.offset > 0) {
            const buf_rem = Blake2.digest_length - self.offset;
            if (n < buf_rem) {
                mem.copy(u8, out_slice, self.buffer[self.offset..][0..out_slice.len]);
                self.offset += out_slice.len;
                self.rem -= n;
                return n;
            }
            mem.copy(u8, out_slice, self.buffer[self.offset..]);
            out_slice = out_slice[buf_rem..];
            self.offset = 0;
            self.rem -= buf_rem;
        }

        while (out_slice.len >= Blake2.digest_length) {
            mem.writeIntLittle(u32, self.cfg[8..12], self.node_offset);
            self.node_offset += 1;

            self.initConfig();
            self.b2.update(&self.h0);
            self.b2.final(&self.buffer);

            mem.copy(u8, out_slice, &self.buffer);
            out_slice = out_slice[Blake2.digest_length..];
            self.rem -= Blake2.digest_length;
        }

        if (out_slice.len > 0) {
            if (self.rem < Blake2.digest_length) {
                self.cfg[0] = @intCast(u8, self.rem);
            }
            mem.writeIntLittle(u32, self.cfg[8..12], self.node_offset);
            self.node_offset += 1;

            self.initConfig();
            self.b2.update(&self.h0);
            self.b2.final(&self.buffer);

            mem.copy(u8, out_slice, self.buffer[0..out_slice.len]);
            self.offset = out_slice.len;
            self.rem -= out_slice.len;
        }

        return n;
    }

    fn initConfig(self: *Self) void {
        self.b2.t = 0;
        self.b2.buf_len = 0;
        for (self.b2.h) |_, i| {
            self.b2.h[i] = iv[i] ^ mem.readIntSliceLittle(u64, self.cfg[i * 8 ..]);
        }
    }
};

pub const Blake2Xs = struct {
    const Self = @This();
    const Blake2 = std.crypto.hash.blake2.Blake2s256;
    const magic_unknown_output_len = 65535;
    const max_output_len = (1 << 32) * 32;
    const iv = [8]u32{
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    };
    pub const Options = Blake2.Options;

    b2: Blake2,
    len: usize,
    rem: usize,
    cfg: [Blake2.digest_length]u8,
    h0: [Blake2.digest_length]u8,
    buffer: [Blake2.digest_length]u8,
    offset: usize,
    node_offset: u32,
    read_mode: bool,

    pub fn init(size: usize, options: Options) Self {
        std.debug.assert(size != magic_unknown_output_len);
        std.debug.assert(size < 0xffff);
        if (options.key) |v| {
            std.debug.assert(v.len <= Blake2.key_length_max);
        }

        var len = size;
        if (len == output_len_unknown) {
            len = magic_unknown_output_len;
        }

        var self: Self = undefined;
        self.b2 = Blake2.init(options);
        self.b2.h[3] ^= @intCast(u32, len);
        self.len = len;

        self.rem = len;
        if (self.rem == magic_unknown_output_len) {
            self.rem = max_output_len;
        }

        mem.set(u8, &self.cfg, 0);
        self.cfg[0] = Blake2.digest_length;
        mem.writeIntLittle(u32, self.cfg[4..8], Blake2.digest_length);
        mem.writeIntLittle(u16, self.cfg[12..14], @intCast(u16, self.len));
        self.cfg[15] = Blake2.digest_length;
        if (options.salt) |v| {
            mem.copy(u8, self.cfg[16..], &v);
        }
        if (options.context) |v| {
            mem.copy(u8, self.cfg[24..], &v);
        }

        self.offset = 0;
        self.node_offset = 0;
        self.read_mode = false;

        return self;
    }

    pub fn update(self: *Self, data: []const u8) void {
        if (self.read_mode) {
            std.debug.panic("blake2xs: write after read", .{});
        }
        self.b2.update(data);
    }

    pub fn read(self: *Self, out: []u8) usize {
        if (!self.read_mode) {
            self.b2.final(&self.h0);
            self.read_mode = true;
        }

        if (self.rem == 0) {
            return 0;
        }

        var out_slice = out;
        var n = out_slice.len;
        if (n > self.rem) {
            n = self.rem;
            out_slice = out_slice[0..n];
        }

        if (self.offset > 0) {
            const buf_rem = Blake2.digest_length - self.offset;
            if (n < buf_rem) {
                mem.copy(u8, out_slice, self.buffer[self.offset..][0..out_slice.len]);
                self.offset += out_slice.len;
                self.rem -= n;
                return n;
            }
            mem.copy(u8, out_slice, self.buffer[self.offset..]);
            out_slice = out_slice[buf_rem..];
            self.offset = 0;
            self.rem -= buf_rem;
        }

        while (out_slice.len >= Blake2.digest_length) {
            mem.writeIntLittle(u32, self.cfg[8..12], self.node_offset);
            self.node_offset += 1;

            self.initConfig();
            self.b2.update(&self.h0);
            self.b2.final(&self.buffer);

            mem.copy(u8, out_slice, &self.buffer);
            out_slice = out_slice[Blake2.digest_length..];
            self.rem -= Blake2.digest_length;
        }

        if (out_slice.len > 0) {
            if (self.rem < Blake2.digest_length) {
                self.cfg[0] = @intCast(u8, self.rem);
            }
            mem.writeIntLittle(u32, self.cfg[8..12], self.node_offset);
            self.node_offset += 1;

            self.initConfig();
            self.b2.update(&self.h0);
            self.b2.final(&self.buffer);

            mem.copy(u8, out_slice, self.buffer[0..out_slice.len]);
            self.offset = out_slice.len;
            self.rem -= out_slice.len;
        }

        return n;
    }

    fn initConfig(self: *Self) void {
        self.b2.t = 0;
        self.b2.buf_len = 0;
        for (self.b2.h) |_, i| {
            self.b2.h[i] = iv[i] ^ mem.readIntSliceLittle(u32, self.cfg[i * 4 ..]);
        }
    }
};

test "blake2xb" {
    const hashes = @import("test_data.zig").xb;
    const key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    var key: [key_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);

    var input: [256]u8 = undefined;
    for (input) |_, i| {
        input[i] = @intCast(u8, i);
    }

    inline for (hashes) |hash_hex| {
        const len = hash_hex.len / 2;
        var hash: [len]u8 = undefined;
        var sum: [len]u8 = undefined;

        _ = try std.fmt.hexToBytes(&hash, hash_hex);

        var xof = Blake2Xb.init(len, .{ .key = &key });
        xof.update(&input);
        try std.testing.expect(xof.read(&sum) == len);
        try std.testing.expect(xof.read(&sum) == 0);

        try std.testing.expectEqualSlices(u8, &hash, &sum);

        xof = Blake2Xb.init(len, .{ .key = &key });
        for (input) |_, j| {
            xof.update(input[j .. j + 1]);
        }
        for (sum) |_, j| {
            _ = try std.testing.expect(xof.read(sum[j .. j + 1]) == 1);
        }

        try std.testing.expectEqualSlices(u8, &hash, &sum);
    }

    var xof = Blake2Xb.init(output_len_unknown, .{ .key = &key });
    xof.update(&input);

    var sum: [64]u8 = undefined;
    try std.testing.expect(xof.read(&sum) == sum.len);

    const hash_hex = "3dbba8516da76bf7330055c66ea36cf1005e92714262b24d9710f51d9e126406e1bcd6497059f9331f1091c3634b695428d475ed432f987040575520a1c29f5e";
    var hash: [hash_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hash, hash_hex);
    try std.testing.expectEqualSlices(u8, &hash, &sum);
}

test "blake2xs" {
    const hashes = @import("test_data.zig").xs;
    const key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    var key: [key_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);

    var input: [256]u8 = undefined;
    for (input) |_, i| {
        input[i] = @intCast(u8, i);
    }

    inline for (hashes) |hash_hex| {
        const len = hash_hex.len / 2;
        var hash: [len]u8 = undefined;
        var sum: [len]u8 = undefined;

        _ = try std.fmt.hexToBytes(&hash, hash_hex);

        var xof = Blake2Xs.init(len, .{ .key = &key });
        xof.update(&input);
        try std.testing.expect(xof.read(&sum) == len);
        try std.testing.expect(xof.read(&sum) == 0);

        try std.testing.expectEqualSlices(u8, &hash, &sum);

        xof = Blake2Xs.init(len, .{ .key = &key });
        for (input) |_, j| {
            xof.update(input[j .. j + 1]);
        }
        for (sum) |_, j| {
            _ = try std.testing.expect(xof.read(sum[j .. j + 1]) == 1);
        }

        try std.testing.expectEqualSlices(u8, &hash, &sum);
    }

    var xof = Blake2Xs.init(output_len_unknown, .{ .key = &key });
    xof.update(&input);

    var sum: [64]u8 = undefined;
    try std.testing.expect(xof.read(&sum) == sum.len);

    const hash_hex = "2a9a6977d915a2c4dd07dbcafe1918bf1682e56d9c8e567ecd19bfd7cd93528833c764d12b34a5e2a219c9fd463dab45e972c5574d73f45de5b2e23af72530d8";
    var hash: [hash_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hash, hash_hex);
    try std.testing.expectEqualSlices(u8, &hash, &sum);
}
