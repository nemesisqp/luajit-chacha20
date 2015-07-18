local ffi = require('ffi')
local bit = require('bit')

local min = math.min
local sizeof = ffi.sizeof
local lshift, rshift, bor, band, bxor = bit.lshift, bit.rshift, bit.bor, bit.band, bit.bxor

local constants = ffi.cast('uint8_t*', 'expand 32-byte k')

local function ROTL32(v, n)
    return bor(lshift(v, n), rshift(v, (32 - n)))
end

local function LE(p)
    p = ffi.cast('uint8_t*', p)
    return bor(ffi.cast('uint32_t', p[0]),
        lshift(ffi.cast('uint32_t', p[1]), 8),
        lshift(ffi.cast('uint32_t', p[2]), 16),
        lshift(ffi.cast('uint32_t', p[3]), 24))
end

local function FROMLE(b, i)
    b = ffi.cast('uint8_t*', b)
    b[0] = band(i, 0xFF)
    b[1] = band(rshift(i, 8), 0xFF)
    b[2] = band(rshift(i, 16), 0xFF)
    b[3] = band(rshift(i, 24), 0xFF)
end

local chacha20 = {}
chacha20.__index = chacha20

ffi.cdef([[
    typedef struct {
        uint32_t schedule[16];
        uint32_t keystream[16];
        size_t available;
    } chacha20_ctx;
]])

local Chacha20Ctx = ffi.metatype('chacha20_ctx', chacha20)

chacha20.test = function()
    local input = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'


    local e = chacha20.new('11223344556677889910111213141516', '12345678')
    local encrypted = ffi.new('uint8_t[?]', #input)
    e:encrypt(input, encrypted, #input)
--    print('encrypted', ffi.string(encrypted, #input))


    local d = chacha20.new('11223344556677889910111213141516', '12345678')
    local decrypted = ffi.new('uint8_t[?]', #input)
    d:decrypt(encrypted, decrypted, #input)
--    print('decrypted', ffi.string(decrypted, #input))
    print('decrypted match original:', ffi.string(decrypted, #input) == input)
    error('exit')
end

function chacha20.new(key, nonce)
    if type(key) == 'string' then
        assert(#key == 32, 'key len must be 32 byte')
        key = ffi.cast('uint8_t*', key)
    end

    if type(nonce) == 'string' then
        assert(#nonce == 8, 'nonce len must be 8 byte')
        nonce = ffi.cast('uint8_t*', nonce)
    end

    local ctx = Chacha20Ctx()

    ctx.schedule[0] = LE(constants + 0)
    ctx.schedule[1] = LE(constants + 4)
    ctx.schedule[2] = LE(constants + 8)
    ctx.schedule[3] = LE(constants + 12)
    ctx.schedule[4] = LE(key + 0)
    ctx.schedule[5] = LE(key + 4)
    ctx.schedule[6] = LE(key + 8)
    ctx.schedule[7] = LE(key + 12)
    ctx.schedule[8] = LE(key + 16)
    ctx.schedule[9] = LE(key + 20)
    ctx.schedule[10] = LE(key + 24)
    ctx.schedule[11] = LE(key + 28)

    ctx.schedule[12] = 0
    ctx.schedule[13] = 0
    ctx.schedule[14] = LE(nonce + 0)
    ctx.schedule[15] = LE(nonce + 4)

    ffi.fill(ctx.keystream, 64, 0)
    ctx.available = 0

    return ctx
end

local function chacha20Xor(keystream, input, output, length)
    local end_keystream = ffi.cast('uint8_t*', keystream + length)
    repeat
        output[0] = bxor(input[0], keystream[0])

        input = input + 1
        output = output + 1
        keystream = keystream + 1
    until keystream == end_keystream
    return input, output
end

local function QUARTERROUND(x, a, b, c, d)
    x[a] = x[a] + x[b]
    x[d] = ROTL32(bxor(x[d], x[a]), 16)

    x[c] = x[c] + x[d]
    x[b] = ROTL32(bxor(x[b], x[c]), 12)

    x[a] = x[a] + x[b]
    x[d] = ROTL32(bxor(x[d], x[a]), 8)

    x[c] = x[c] + x[d]
    x[b] = ROTL32(bxor(x[b], x[c]), 7)
end

local function chacha20Block(ctx, out)
    local nonce = ffi.cast('uint32_t*', ctx.schedule + 12)

    ffi.copy(out, ctx.schedule, ffi.sizeof(ctx.schedule))

    for i = 1, 10 do
        out[0] = out[0] + out[4]
        out[12] = ROTL32(bxor(out[12], out[0]), 16)
        out[8] = out[8] + out[12]
        out[4] = ROTL32(bxor(out[4], out[8]), 12)
        out[0] = out[0] + out[4]
        out[12] = ROTL32(bxor(out[12], out[0]), 8)
        out[8] = out[8] + out[12]
        out[4] = ROTL32(bxor(out[4], out[8]), 7)

        out[1] = out[1] + out[5]
        out[13] = ROTL32(bxor(out[13], out[1]), 16)
        out[9] = out[9] + out[13]
        out[5] = ROTL32(bxor(out[5], out[9]), 12)
        out[1] = out[1] + out[5]
        out[13] = ROTL32(bxor(out[13], out[1]), 8)
        out[9] = out[9] + out[13]
        out[5] = ROTL32(bxor(out[5], out[9]), 7)

        out[2] = out[2] + out[6]
        out[14] = ROTL32(bxor(out[14], out[2]), 16)
        out[10] = out[10] + out[14]
        out[6] = ROTL32(bxor(out[6], out[10]), 12)
        out[2] = out[2] + out[6]
        out[14] = ROTL32(bxor(out[14], out[2]), 8)
        out[10] = out[10] + out[14]
        out[6] = ROTL32(bxor(out[6], out[10]), 7)

        out[3] = out[3] + out[7]
        out[15] = ROTL32(bxor(out[15], out[3]), 16)
        out[11] = out[11] + out[15]
        out[7] = ROTL32(bxor(out[7], out[11]), 12)
        out[3] = out[3] + out[7]
        out[15] = ROTL32(bxor(out[15], out[3]), 8)
        out[11] = out[11] + out[15]
        out[7] = ROTL32(bxor(out[7], out[11]), 7)

        out[0] = out[0] + out[5]
        out[15] = ROTL32(bxor(out[15], out[0]), 16)
        out[10] = out[10] + out[15]
        out[5] = ROTL32(bxor(out[5], out[10]), 12)
        out[0] = out[0] + out[5]
        out[15] = ROTL32(bxor(out[15], out[0]), 8)
        out[10] = out[10] + out[15]
        out[5] = ROTL32(bxor(out[5], out[10]), 7)

        out[1] = out[1] + out[6]
        out[12] = ROTL32(bxor(out[12], out[1]), 16)
        out[11] = out[11] + out[12]
        out[6] = ROTL32(bxor(out[6], out[11]), 12)
        out[1] = out[1] + out[6]
        out[12] = ROTL32(bxor(out[12], out[1]), 8)
        out[11] = out[11] + out[12]
        out[6] = ROTL32(bxor(out[6], out[11]), 7)

        out[2] = out[2] + out[7]
        out[13] = ROTL32(bxor(out[13], out[2]), 16)
        out[8] = out[8] + out[13]
        out[7] = ROTL32(bxor(out[7], out[8]), 12)
        out[2] = out[2] + out[7]
        out[13] = ROTL32(bxor(out[13], out[2]), 8)
        out[8] = out[8] + out[13]
        out[7] = ROTL32(bxor(out[7], out[8]), 7)

        out[3] = out[3] + out[4]
        out[14] = ROTL32(bxor(out[14], out[3]), 16)
        out[9] = out[9] + out[14]
        out[4] = ROTL32(bxor(out[4], out[9]), 12)
        out[3] = out[3] + out[4]
        out[14] = ROTL32(bxor(out[14], out[3]), 8)
        out[9] = out[9] + out[14]
        out[4] = ROTL32(bxor(out[4], out[9]), 7)

        -- why this fail ? o_O
--        QUARTERROUND(out, 0, 4, 8, 12)
--        QUARTERROUND(out, 1, 5, 9, 13)
--        QUARTERROUND(out, 2, 6, 10, 14)
--        QUARTERROUND(out, 3, 7, 11, 15)
--        QUARTERROUND(out, 0, 5, 10, 15)
--        QUARTERROUND(out, 1, 6, 11, 12)
--        QUARTERROUND(out, 2, 7, 8, 13)
--        QUARTERROUND(out, 3, 4, 9, 14)
    end

    for i = 0, 16 do
        FROMLE(out + i, out[i] + ctx.schedule[i])
    end

    nonce[0] = nonce[0] + 1
    if nonce[0] ~= 0 then return end

    nonce[1] = nonce[1] + 1
    if nonce[1] ~= 0 then return end

    nonce[2] = nonce[2] + 1
    if nonce[2] ~= 0 then return end
    nonce[3] = nonce[3] + 1
end

function chacha20.encrypt(self, input, output, length)
    input = ffi.cast('uint8_t*', input)
    output = ffi.cast('uint8_t*', output)

    if length <= 0 then return end
    local k = ffi.cast('uint8_t*', self.keystream)

    local keystreamLen = sizeof(self.keystream)
    if self.available > 0 then
        local amount = min(length, self.available)
        input, output = chacha20Xor(k + (keystreamLen - self.available), input, output, amount)
        self.available = self.available - amount
        length = length - amount
    end

    while length > 0 do
        local amount = min(length, keystreamLen)
        chacha20Block(self, self.keystream)
        input, output = chacha20Xor(k, input, output, amount)
        length = length - amount
        self.available = keystreamLen - amount
    end
end

function chacha20.counterSet(self, counter)
    self.schedule[12] = band(counter, 0xFFFFFFFF)
    self.schedule[13] = rshift(counter, 32)
    self.available = 0
end

chacha20.decrypt = chacha20.encrypt

return chacha20
