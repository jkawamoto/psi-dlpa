# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: dlpa/dlpa.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='dlpa/dlpa.proto',
  package='dlpa',
  syntax='proto3',
  serialized_pb=_b('\n\x0f\x64lpa/dlpa.proto\x12\x04\x64lpa\"2\n\tPublicKey\x12\t\n\x01m\x18\x01 \x01(\t\x12\t\n\x01g\x18\x02 \x01(\t\x12\x0f\n\x07glambda\x18\x03 \x01(\t\"X\n\tClientKey\x12\x10\n\x08lambda_u\x18\x01 \x01(\t\x12\t\n\x01\x61\x18\x02 \x01(\t\x12\t\n\x01\x62\x18\x03 \x01(\t\x12#\n\npublic_key\x18\x04 \x01(\x0b\x32\x0f.dlpa.PublicKey\"\x1b\n\rGetKeyRequest\x12\n\n\x02id\x18\x01 \x01(\x05\"E\n\nCiphertext\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04time\x18\x02 \x01(\x05\x12\r\n\x05value\x18\x03 \x03(\t\x12\x0e\n\x06target\x18\x04 \x01(\t\"J\n\x0f\x44\x65\x63ryptionShare\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04slot\x18\x02 \x01(\x05\x12\r\n\x05share\x18\x03 \x03(\t\x12\x0e\n\x06target\x18\x04 \x01(\t\"N\n\x10\x43iphertextVector\x12\n\n\x02\x63\x31\x18\x01 \x03(\t\x12\n\n\x02\x63\x32\x18\x02 \x03(\t\x12\n\n\x02\x63\x33\x18\x03 \x03(\t\x12\n\n\x02\x63\x34\x18\x04 \x03(\t\x12\n\n\x02\x63\x35\x18\x05 \x03(\t\"m\n\x1a\x45ncryptNoisySumCiphertexts\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04time\x18\x02 \x01(\x05\x12%\n\x05value\x18\x03 \x01(\x0b\x32\x16.dlpa.CiphertextVector\x12\x0e\n\x06target\x18\x04 \x01(\t\"\x0c\n\nNoResponse2\xad\x04\n\x04\x44LPA\x12\x30\n\x06GetKey\x12\x13.dlpa.GetKeyRequest\x1a\x0f.dlpa.ClientKey\"\x00\x12\x35\n\rPutEncryptSum\x12\x10.dlpa.Ciphertext\x1a\x10.dlpa.Ciphertext\"\x00\x12?\n\x12PutEncryptSumShare\x12\x15.dlpa.DecryptionShare\x1a\x10.dlpa.NoResponse\"\x00\x12<\n\x14PutEncryptSumSquared\x12\x10.dlpa.Ciphertext\x1a\x10.dlpa.Ciphertext\"\x00\x12\x46\n\x19PutEncryptSumSquaredShare\x12\x15.dlpa.DecryptionShare\x1a\x10.dlpa.NoResponse\"\x00\x12Z\n\x12PutEncryptNoisySum\x12 .dlpa.EncryptNoisySumCiphertexts\x1a .dlpa.EncryptNoisySumCiphertexts\"\x00\x12O\n\x17PutEncryptNoisySumShare\x12 .dlpa.EncryptNoisySumCiphertexts\x1a\x10.dlpa.Ciphertext\"\x00\x12H\n\x1bPutEncryptNoisySumLastShare\x12\x15.dlpa.DecryptionShare\x1a\x10.dlpa.NoResponse\"\x00\x62\x06proto3')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_PUBLICKEY = _descriptor.Descriptor(
  name='PublicKey',
  full_name='dlpa.PublicKey',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='m', full_name='dlpa.PublicKey.m', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='g', full_name='dlpa.PublicKey.g', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='glambda', full_name='dlpa.PublicKey.glambda', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=25,
  serialized_end=75,
)


_CLIENTKEY = _descriptor.Descriptor(
  name='ClientKey',
  full_name='dlpa.ClientKey',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='lambda_u', full_name='dlpa.ClientKey.lambda_u', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='a', full_name='dlpa.ClientKey.a', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='b', full_name='dlpa.ClientKey.b', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='dlpa.ClientKey.public_key', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=77,
  serialized_end=165,
)


_GETKEYREQUEST = _descriptor.Descriptor(
  name='GetKeyRequest',
  full_name='dlpa.GetKeyRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='dlpa.GetKeyRequest.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=167,
  serialized_end=194,
)


_CIPHERTEXT = _descriptor.Descriptor(
  name='Ciphertext',
  full_name='dlpa.Ciphertext',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='dlpa.Ciphertext.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='time', full_name='dlpa.Ciphertext.time', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='dlpa.Ciphertext.value', index=2,
      number=3, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='target', full_name='dlpa.Ciphertext.target', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=196,
  serialized_end=265,
)


_DECRYPTIONSHARE = _descriptor.Descriptor(
  name='DecryptionShare',
  full_name='dlpa.DecryptionShare',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='dlpa.DecryptionShare.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='slot', full_name='dlpa.DecryptionShare.slot', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='share', full_name='dlpa.DecryptionShare.share', index=2,
      number=3, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='target', full_name='dlpa.DecryptionShare.target', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=267,
  serialized_end=341,
)


_CIPHERTEXTVECTOR = _descriptor.Descriptor(
  name='CiphertextVector',
  full_name='dlpa.CiphertextVector',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='c1', full_name='dlpa.CiphertextVector.c1', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='c2', full_name='dlpa.CiphertextVector.c2', index=1,
      number=2, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='c3', full_name='dlpa.CiphertextVector.c3', index=2,
      number=3, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='c4', full_name='dlpa.CiphertextVector.c4', index=3,
      number=4, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='c5', full_name='dlpa.CiphertextVector.c5', index=4,
      number=5, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=343,
  serialized_end=421,
)


_ENCRYPTNOISYSUMCIPHERTEXTS = _descriptor.Descriptor(
  name='EncryptNoisySumCiphertexts',
  full_name='dlpa.EncryptNoisySumCiphertexts',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='dlpa.EncryptNoisySumCiphertexts.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='time', full_name='dlpa.EncryptNoisySumCiphertexts.time', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='dlpa.EncryptNoisySumCiphertexts.value', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='target', full_name='dlpa.EncryptNoisySumCiphertexts.target', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=423,
  serialized_end=532,
)


_NORESPONSE = _descriptor.Descriptor(
  name='NoResponse',
  full_name='dlpa.NoResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=534,
  serialized_end=546,
)

_CLIENTKEY.fields_by_name['public_key'].message_type = _PUBLICKEY
_ENCRYPTNOISYSUMCIPHERTEXTS.fields_by_name['value'].message_type = _CIPHERTEXTVECTOR
DESCRIPTOR.message_types_by_name['PublicKey'] = _PUBLICKEY
DESCRIPTOR.message_types_by_name['ClientKey'] = _CLIENTKEY
DESCRIPTOR.message_types_by_name['GetKeyRequest'] = _GETKEYREQUEST
DESCRIPTOR.message_types_by_name['Ciphertext'] = _CIPHERTEXT
DESCRIPTOR.message_types_by_name['DecryptionShare'] = _DECRYPTIONSHARE
DESCRIPTOR.message_types_by_name['CiphertextVector'] = _CIPHERTEXTVECTOR
DESCRIPTOR.message_types_by_name['EncryptNoisySumCiphertexts'] = _ENCRYPTNOISYSUMCIPHERTEXTS
DESCRIPTOR.message_types_by_name['NoResponse'] = _NORESPONSE

PublicKey = _reflection.GeneratedProtocolMessageType('PublicKey', (_message.Message,), dict(
  DESCRIPTOR = _PUBLICKEY,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.PublicKey)
  ))
_sym_db.RegisterMessage(PublicKey)

ClientKey = _reflection.GeneratedProtocolMessageType('ClientKey', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTKEY,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.ClientKey)
  ))
_sym_db.RegisterMessage(ClientKey)

GetKeyRequest = _reflection.GeneratedProtocolMessageType('GetKeyRequest', (_message.Message,), dict(
  DESCRIPTOR = _GETKEYREQUEST,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.GetKeyRequest)
  ))
_sym_db.RegisterMessage(GetKeyRequest)

Ciphertext = _reflection.GeneratedProtocolMessageType('Ciphertext', (_message.Message,), dict(
  DESCRIPTOR = _CIPHERTEXT,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.Ciphertext)
  ))
_sym_db.RegisterMessage(Ciphertext)

DecryptionShare = _reflection.GeneratedProtocolMessageType('DecryptionShare', (_message.Message,), dict(
  DESCRIPTOR = _DECRYPTIONSHARE,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.DecryptionShare)
  ))
_sym_db.RegisterMessage(DecryptionShare)

CiphertextVector = _reflection.GeneratedProtocolMessageType('CiphertextVector', (_message.Message,), dict(
  DESCRIPTOR = _CIPHERTEXTVECTOR,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.CiphertextVector)
  ))
_sym_db.RegisterMessage(CiphertextVector)

EncryptNoisySumCiphertexts = _reflection.GeneratedProtocolMessageType('EncryptNoisySumCiphertexts', (_message.Message,), dict(
  DESCRIPTOR = _ENCRYPTNOISYSUMCIPHERTEXTS,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.EncryptNoisySumCiphertexts)
  ))
_sym_db.RegisterMessage(EncryptNoisySumCiphertexts)

NoResponse = _reflection.GeneratedProtocolMessageType('NoResponse', (_message.Message,), dict(
  DESCRIPTOR = _NORESPONSE,
  __module__ = 'dlpa.dlpa_pb2'
  # @@protoc_insertion_point(class_scope:dlpa.NoResponse)
  ))
_sym_db.RegisterMessage(NoResponse)


try:
  # THESE ELEMENTS WILL BE DEPRECATED.
  # Please use the generated *_pb2_grpc.py files instead.
  import grpc
  from grpc.framework.common import cardinality
  from grpc.framework.interfaces.face import utilities as face_utilities
  from grpc.beta import implementations as beta_implementations
  from grpc.beta import interfaces as beta_interfaces


  class DLPAStub(object):
    """DLPA defines the interface of distributed Laplace Perturbation
    Algorithm (DLPA) service.
    """

    def __init__(self, channel):
      """Constructor.

      Args:
        channel: A grpc.Channel.
      """
      self.GetKey = channel.unary_unary(
          '/dlpa.DLPA/GetKey',
          request_serializer=GetKeyRequest.SerializeToString,
          response_deserializer=ClientKey.FromString,
          )
      self.PutEncryptSum = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptSum',
          request_serializer=Ciphertext.SerializeToString,
          response_deserializer=Ciphertext.FromString,
          )
      self.PutEncryptSumShare = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptSumShare',
          request_serializer=DecryptionShare.SerializeToString,
          response_deserializer=NoResponse.FromString,
          )
      self.PutEncryptSumSquared = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptSumSquared',
          request_serializer=Ciphertext.SerializeToString,
          response_deserializer=Ciphertext.FromString,
          )
      self.PutEncryptSumSquaredShare = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptSumSquaredShare',
          request_serializer=DecryptionShare.SerializeToString,
          response_deserializer=NoResponse.FromString,
          )
      self.PutEncryptNoisySum = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptNoisySum',
          request_serializer=EncryptNoisySumCiphertexts.SerializeToString,
          response_deserializer=EncryptNoisySumCiphertexts.FromString,
          )
      self.PutEncryptNoisySumShare = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptNoisySumShare',
          request_serializer=EncryptNoisySumCiphertexts.SerializeToString,
          response_deserializer=Ciphertext.FromString,
          )
      self.PutEncryptNoisySumLastShare = channel.unary_unary(
          '/dlpa.DLPA/PutEncryptNoisySumLastShare',
          request_serializer=DecryptionShare.SerializeToString,
          response_deserializer=NoResponse.FromString,
          )


  class DLPAServicer(object):
    """DLPA defines the interface of distributed Laplace Perturbation
    Algorithm (DLPA) service.
    """

    def GetKey(self, request, context):
      """GetKey is used in the setup phase to obtain keys.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptSum(self, request, context):
      """PutEncryptSum is used in the first step of Encrypt-Sum protocol, to
      upload a ciphertext. It returns an aggregated ciphertext to create a
      decription share.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptSumShare(self, request, context):
      """PutEncryptSumShare is used in the second step of Encrypt-Sum protocol, to
      upload a decryption share.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptSumSquared(self, request, context):
      """PutEncryptSumSquared is used in the first step of Encrypt-Sum-Squared
      protocol, to upload a Ciphertext. It returns an aggregated ciphertext to
      create a decryption share.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptSumSquaredShare(self, request, context):
      """PutEncryptSumSquaredShare is used in the second step of Encrypt-Sum-Squared
      protocol, to upload a decryption share.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptNoisySum(self, request, context):
      """PutEncryptNoisySum is used in the first step of Encrypt-Noisy-Sum protocol,
      to upload a ciphertext. It returns an aggregated ciphertext to create a
      decription share.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptNoisySumShare(self, request, context):
      """PutEncryptNoisySumShare is used in the second step of Encrypt-Noisy-Sum
      protocol, to upload a set of decryption shares.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')

    def PutEncryptNoisySumLastShare(self, request, context):
      """PutEncryptNoisySumShare is used in the second step of Encrypt-Noisy-Sum
      protocol, to upload a last decryption share.
      """
      context.set_code(grpc.StatusCode.UNIMPLEMENTED)
      context.set_details('Method not implemented!')
      raise NotImplementedError('Method not implemented!')


  def add_DLPAServicer_to_server(servicer, server):
    rpc_method_handlers = {
        'GetKey': grpc.unary_unary_rpc_method_handler(
            servicer.GetKey,
            request_deserializer=GetKeyRequest.FromString,
            response_serializer=ClientKey.SerializeToString,
        ),
        'PutEncryptSum': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptSum,
            request_deserializer=Ciphertext.FromString,
            response_serializer=Ciphertext.SerializeToString,
        ),
        'PutEncryptSumShare': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptSumShare,
            request_deserializer=DecryptionShare.FromString,
            response_serializer=NoResponse.SerializeToString,
        ),
        'PutEncryptSumSquared': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptSumSquared,
            request_deserializer=Ciphertext.FromString,
            response_serializer=Ciphertext.SerializeToString,
        ),
        'PutEncryptSumSquaredShare': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptSumSquaredShare,
            request_deserializer=DecryptionShare.FromString,
            response_serializer=NoResponse.SerializeToString,
        ),
        'PutEncryptNoisySum': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptNoisySum,
            request_deserializer=EncryptNoisySumCiphertexts.FromString,
            response_serializer=EncryptNoisySumCiphertexts.SerializeToString,
        ),
        'PutEncryptNoisySumShare': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptNoisySumShare,
            request_deserializer=EncryptNoisySumCiphertexts.FromString,
            response_serializer=Ciphertext.SerializeToString,
        ),
        'PutEncryptNoisySumLastShare': grpc.unary_unary_rpc_method_handler(
            servicer.PutEncryptNoisySumLastShare,
            request_deserializer=DecryptionShare.FromString,
            response_serializer=NoResponse.SerializeToString,
        ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
        'dlpa.DLPA', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


  class BetaDLPAServicer(object):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This class was generated
    only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0."""
    """DLPA defines the interface of distributed Laplace Perturbation
    Algorithm (DLPA) service.
    """
    def GetKey(self, request, context):
      """GetKey is used in the setup phase to obtain keys.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptSum(self, request, context):
      """PutEncryptSum is used in the first step of Encrypt-Sum protocol, to
      upload a ciphertext. It returns an aggregated ciphertext to create a
      decription share.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptSumShare(self, request, context):
      """PutEncryptSumShare is used in the second step of Encrypt-Sum protocol, to
      upload a decryption share.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptSumSquared(self, request, context):
      """PutEncryptSumSquared is used in the first step of Encrypt-Sum-Squared
      protocol, to upload a Ciphertext. It returns an aggregated ciphertext to
      create a decryption share.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptSumSquaredShare(self, request, context):
      """PutEncryptSumSquaredShare is used in the second step of Encrypt-Sum-Squared
      protocol, to upload a decryption share.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptNoisySum(self, request, context):
      """PutEncryptNoisySum is used in the first step of Encrypt-Noisy-Sum protocol,
      to upload a ciphertext. It returns an aggregated ciphertext to create a
      decription share.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptNoisySumShare(self, request, context):
      """PutEncryptNoisySumShare is used in the second step of Encrypt-Noisy-Sum
      protocol, to upload a set of decryption shares.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)
    def PutEncryptNoisySumLastShare(self, request, context):
      """PutEncryptNoisySumShare is used in the second step of Encrypt-Noisy-Sum
      protocol, to upload a last decryption share.
      """
      context.code(beta_interfaces.StatusCode.UNIMPLEMENTED)


  class BetaDLPAStub(object):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This class was generated
    only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0."""
    """DLPA defines the interface of distributed Laplace Perturbation
    Algorithm (DLPA) service.
    """
    def GetKey(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """GetKey is used in the setup phase to obtain keys.
      """
      raise NotImplementedError()
    GetKey.future = None
    def PutEncryptSum(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptSum is used in the first step of Encrypt-Sum protocol, to
      upload a ciphertext. It returns an aggregated ciphertext to create a
      decription share.
      """
      raise NotImplementedError()
    PutEncryptSum.future = None
    def PutEncryptSumShare(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptSumShare is used in the second step of Encrypt-Sum protocol, to
      upload a decryption share.
      """
      raise NotImplementedError()
    PutEncryptSumShare.future = None
    def PutEncryptSumSquared(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptSumSquared is used in the first step of Encrypt-Sum-Squared
      protocol, to upload a Ciphertext. It returns an aggregated ciphertext to
      create a decryption share.
      """
      raise NotImplementedError()
    PutEncryptSumSquared.future = None
    def PutEncryptSumSquaredShare(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptSumSquaredShare is used in the second step of Encrypt-Sum-Squared
      protocol, to upload a decryption share.
      """
      raise NotImplementedError()
    PutEncryptSumSquaredShare.future = None
    def PutEncryptNoisySum(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptNoisySum is used in the first step of Encrypt-Noisy-Sum protocol,
      to upload a ciphertext. It returns an aggregated ciphertext to create a
      decription share.
      """
      raise NotImplementedError()
    PutEncryptNoisySum.future = None
    def PutEncryptNoisySumShare(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptNoisySumShare is used in the second step of Encrypt-Noisy-Sum
      protocol, to upload a set of decryption shares.
      """
      raise NotImplementedError()
    PutEncryptNoisySumShare.future = None
    def PutEncryptNoisySumLastShare(self, request, timeout, metadata=None, with_call=False, protocol_options=None):
      """PutEncryptNoisySumShare is used in the second step of Encrypt-Noisy-Sum
      protocol, to upload a last decryption share.
      """
      raise NotImplementedError()
    PutEncryptNoisySumLastShare.future = None


  def beta_create_DLPA_server(servicer, pool=None, pool_size=None, default_timeout=None, maximum_timeout=None):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This function was
    generated only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0"""
    request_deserializers = {
      ('dlpa.DLPA', 'GetKey'): GetKeyRequest.FromString,
      ('dlpa.DLPA', 'PutEncryptNoisySum'): EncryptNoisySumCiphertexts.FromString,
      ('dlpa.DLPA', 'PutEncryptNoisySumLastShare'): DecryptionShare.FromString,
      ('dlpa.DLPA', 'PutEncryptNoisySumShare'): EncryptNoisySumCiphertexts.FromString,
      ('dlpa.DLPA', 'PutEncryptSum'): Ciphertext.FromString,
      ('dlpa.DLPA', 'PutEncryptSumShare'): DecryptionShare.FromString,
      ('dlpa.DLPA', 'PutEncryptSumSquared'): Ciphertext.FromString,
      ('dlpa.DLPA', 'PutEncryptSumSquaredShare'): DecryptionShare.FromString,
    }
    response_serializers = {
      ('dlpa.DLPA', 'GetKey'): ClientKey.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptNoisySum'): EncryptNoisySumCiphertexts.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptNoisySumLastShare'): NoResponse.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptNoisySumShare'): Ciphertext.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSum'): Ciphertext.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSumShare'): NoResponse.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSumSquared'): Ciphertext.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSumSquaredShare'): NoResponse.SerializeToString,
    }
    method_implementations = {
      ('dlpa.DLPA', 'GetKey'): face_utilities.unary_unary_inline(servicer.GetKey),
      ('dlpa.DLPA', 'PutEncryptNoisySum'): face_utilities.unary_unary_inline(servicer.PutEncryptNoisySum),
      ('dlpa.DLPA', 'PutEncryptNoisySumLastShare'): face_utilities.unary_unary_inline(servicer.PutEncryptNoisySumLastShare),
      ('dlpa.DLPA', 'PutEncryptNoisySumShare'): face_utilities.unary_unary_inline(servicer.PutEncryptNoisySumShare),
      ('dlpa.DLPA', 'PutEncryptSum'): face_utilities.unary_unary_inline(servicer.PutEncryptSum),
      ('dlpa.DLPA', 'PutEncryptSumShare'): face_utilities.unary_unary_inline(servicer.PutEncryptSumShare),
      ('dlpa.DLPA', 'PutEncryptSumSquared'): face_utilities.unary_unary_inline(servicer.PutEncryptSumSquared),
      ('dlpa.DLPA', 'PutEncryptSumSquaredShare'): face_utilities.unary_unary_inline(servicer.PutEncryptSumSquaredShare),
    }
    server_options = beta_implementations.server_options(request_deserializers=request_deserializers, response_serializers=response_serializers, thread_pool=pool, thread_pool_size=pool_size, default_timeout=default_timeout, maximum_timeout=maximum_timeout)
    return beta_implementations.server(method_implementations, options=server_options)


  def beta_create_DLPA_stub(channel, host=None, metadata_transformer=None, pool=None, pool_size=None):
    """The Beta API is deprecated for 0.15.0 and later.

    It is recommended to use the GA API (classes and functions in this
    file not marked beta) for all further purposes. This function was
    generated only to ease transition from grpcio<0.15.0 to grpcio>=0.15.0"""
    request_serializers = {
      ('dlpa.DLPA', 'GetKey'): GetKeyRequest.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptNoisySum'): EncryptNoisySumCiphertexts.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptNoisySumLastShare'): DecryptionShare.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptNoisySumShare'): EncryptNoisySumCiphertexts.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSum'): Ciphertext.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSumShare'): DecryptionShare.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSumSquared'): Ciphertext.SerializeToString,
      ('dlpa.DLPA', 'PutEncryptSumSquaredShare'): DecryptionShare.SerializeToString,
    }
    response_deserializers = {
      ('dlpa.DLPA', 'GetKey'): ClientKey.FromString,
      ('dlpa.DLPA', 'PutEncryptNoisySum'): EncryptNoisySumCiphertexts.FromString,
      ('dlpa.DLPA', 'PutEncryptNoisySumLastShare'): NoResponse.FromString,
      ('dlpa.DLPA', 'PutEncryptNoisySumShare'): Ciphertext.FromString,
      ('dlpa.DLPA', 'PutEncryptSum'): Ciphertext.FromString,
      ('dlpa.DLPA', 'PutEncryptSumShare'): NoResponse.FromString,
      ('dlpa.DLPA', 'PutEncryptSumSquared'): Ciphertext.FromString,
      ('dlpa.DLPA', 'PutEncryptSumSquaredShare'): NoResponse.FromString,
    }
    cardinalities = {
      'GetKey': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptNoisySum': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptNoisySumLastShare': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptNoisySumShare': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptSum': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptSumShare': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptSumSquared': cardinality.Cardinality.UNARY_UNARY,
      'PutEncryptSumSquaredShare': cardinality.Cardinality.UNARY_UNARY,
    }
    stub_options = beta_implementations.stub_options(host=host, metadata_transformer=metadata_transformer, request_serializers=request_serializers, response_deserializers=response_deserializers, thread_pool=pool, thread_pool_size=pool_size)
    return beta_implementations.dynamic_stub(channel, 'dlpa.DLPA', cardinalities, options=stub_options)
except ImportError:
  pass
# @@protoc_insertion_point(module_scope)
