package golesali

import (
    "io"
    "log"
    "bytes"
    "errors"
    "encoding/binary"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/net/context"
)

// VERSION
const Major = 0
const Minor = 2

// PROTOCOL VERSION
const PROTOCOL_VERSION = 1

// BUFFER LENGTHS
const K_SZ = 32 // key size in bytes
const N_SZ = 24 // nonce size in bytes
const LN_SZ = 6 // length of lesali nonce in bytes

// TYPES
type EstablishContextFunc func(ctx context.Context, pk *[32]byte,
msgNumber uint64) (context.Context, *[32]byte, error)

type UpdateNonceFunc func(ctx context.Context, pk *[32]byte,
msgNumber uint64) error
type RequestHandlerFunc func(ctx context.Context, msg io.Reader,
response io.Writer) error
type PaddingSizeFunc func(int) (int, byte)

type ClientServerDispatcher struct {
    EstablishContext EstablishContextFunc
    UpdateNonce UpdateNonceFunc
    RequestHandler RequestHandlerFunc
    GetPaddingSize PaddingSizeFunc
}

// ## DEFAULT FUNCTIONS ## 
func DefaultPaddingSize(plainLen int) (int, byte) {
    mask := 1
    if plainLen > 255 { return plainLen+1, 1 }
    // default behavior is to pad up to the next power of two
    for mask <= plainLen {
        mask *= 2
    }
    return mask, byte(mask-plainLen)
}

// ## UTILITY FUNCTIONS ##
func StripPadding(padded_msg []byte) ([]byte, error) {
    l := len(padded_msg)
    p := int(padded_msg[l-1])
    if p > l { return nil, errors.New("Padding too long."); }
    if p < 1 { return nil, errors.New("Padding too short."); }
    return padded_msg[0:l-p], nil
}

// ## UNIDIRECTIONAL COMMUNICATION ##
func GetStrippedEnvelopeLen(msgLen int, padding byte) int {
    return msgLen + int(padding) + box.Overhead
}

func GetAnonymousEnvelopeLen(msgLen int, padding byte) int {
    return GetStrippedEnvelopeLen(msgLen, padding) + LN_SZ
}

func GetPublicEnvelopeLen(msgLen int, padding byte) int {
    return GetAnonymousEnvelopeLen(msgLen, padding) + K_SZ
}

func SealStrippedEnvelope(sealed io.Writer, plain io.Reader, ss *[K_SZ]byte,
padding byte, msgNumber uint64) error {
    var (
        plainBuf bytes.Buffer
        cipher []byte
        nonce [N_SZ]byte
    )

    if padding < 1 { return errors.New("padding must be at lest 1.") }

    _, err := io.Copy(&plainBuf, plain)
    if err != nil { return err }

    paddingBuf := make([]byte, padding)
    for i := 0; i < int(padding); i++ { paddingBuf[i] = padding }
    plainBuf.Write(paddingBuf)

    binary.BigEndian.PutUint64(nonce[N_SZ - LN_SZ:], msgNumber)

    cipher = box.SealAfterPrecomputation(cipher[:], plainBuf.Bytes(),
        &nonce, ss)

    sealed.Write(cipher)
    return nil
}

func SealAnonymousEnvelope(sealed io.Writer, plain io.Reader, ss *[K_SZ]byte,
padding byte, msgNumber uint64) error {
    var nonce [8]byte
    binary.BigEndian.PutUint64(nonce[2:], msgNumber)
    sealed.Write(nonce[2:])
    err := SealStrippedEnvelope(sealed, plain, ss, padding, msgNumber)
    return err
}

func SealPublicEnvelope(sealed io.Writer, plain io.Reader, pk_s *[K_SZ]byte,
pk_r *[K_SZ]byte, ss *[K_SZ]byte, padding byte, msgNumber uint64) error {
    sealed.Write(pk_s[:])
    err := SealAnonymousEnvelope(sealed, plain, ss, padding, msgNumber)
    return err
}

// ## CLIENT/SERVER COMMUNICATION ##
func (csd *ClientServerDispatcher) HandleRequest(ctx context.Context,
responseWriter io.Writer, requestReader io.Reader) error {
    var (
        pk [K_SZ]byte
        nonce [N_SZ]byte
        plain []byte
        requestBuffer bytes.Buffer
        plainResponseBuffer bytes.Buffer
        cipher_response []byte
    )

    // extract public key from request
    _, err := requestReader.Read(pk[:])
    if err != nil { return err }
    // extract nonce from request
    _, err = requestReader.Read(nonce[N_SZ-LN_SZ:])
    if err != nil { return err }

    // call GetChannelState
    intNonce := binary.BigEndian.Uint64(nonce[N_SZ-8:])
    if intNonce % 2 != 0 { return errors.New(
        "Incoming requests must have an even message number.") }

    newCtx, ss, err := csd.EstablishContext(ctx, &pk, intNonce)
    if err != nil { return err }

    io.Copy(&requestBuffer, requestReader)
    // decrypt
    plain, success := box.OpenAfterPrecomputation(plain, requestBuffer.Bytes(),
    &nonce, ss)
    if false == success { return errors.New("Authentication error.") }

    if err := csd.UpdateNonce(newCtx, &pk, intNonce); err != nil { return err }

    stripped_plain, err := StripPadding(plain)
    if err != nil { return err }

    // call handleRequest
    strippedBuf := bytes.NewBuffer(stripped_plain)
    if err := csd.RequestHandler(newCtx, strippedBuf,
    &plainResponseBuffer); err != nil { return err }

    binary.BigEndian.PutUint64(nonce[N_SZ-8:], intNonce+1)

    // seal stripped envelope

    _, padding := DefaultPaddingSize(plainResponseBuffer.Len())
    paddingBuf := make([]byte, int(padding))
    for i := 0; i < int(padding); i++ { paddingBuf[i] = padding }
    plainResponseBuffer.Write(paddingBuf)

    plainResponseBytes := plainResponseBuffer.Bytes()
    log.Println(plainResponseBytes)
    cipher_response = box.SealAfterPrecomputation(cipher_response,
    plainResponseBuffer.Bytes(), &nonce, ss)
    responseWriter.Write(cipher_response[:])

    return nil;
}
