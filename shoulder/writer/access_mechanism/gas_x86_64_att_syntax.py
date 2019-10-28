from shoulder.writer.access_mechanism.access_mechanism \
    import AccessMechanismWriter


class GasX86_64AttSyntaxAccessMechanismWriter(AccessMechanismWriter):

    def call_readable_access_mechanism(self, outfile, register,
                                       access_mechanism, var):
        pass

    def call_writable_access_mechanism(self, outfile, register, access_mechanism, value):
        pass
