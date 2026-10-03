// This code is licensed under the BSD 3-Clause license (see LICENSE.txt for details)

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using Org.BouncyCastle.Tls;

namespace Cosmos.Network.Http.Tests;

/// <summary>
/// Chains made up with <see cref="TestPki"/>, each broken one way, checked
/// without a connection.
/// </summary>
[TestFixture]
public class CertificateValidatorTests
{
    private static readonly string[] s_names = ["server.test", "127.0.0.1"];

    private X509Certificate2 _root = null!;
    private X509Certificate2 _intermediate = null!;
    private TrustedRoots _roots = null!;

    [OneTimeSetUp]
    public void CreateRoot()
    {
        _root = TestPki.Root();
        _intermediate = TestPki.Authority(_root);
        _roots = TrustedRoots.FromCertificates([_root.RawData]);
    }

    [Test]
    public void ValidChain_IsTrusted()
    {
        Assert.That(Validate([TestPki.Server(_intermediate, s_names), _intermediate], "server.test"), Is.Null);
    }

    [Test]
    public void ChainWithoutIntermediate_DirectlyUnderTheRoot_IsTrusted()
    {
        Assert.That(Validate([TestPki.Server(_root, s_names)], "server.test"), Is.Null);
    }

    [Test]
    public void IntermediatesInAnyOrder_WithStrangers_AreTrusted()
    {
        X509Certificate2 second = TestPki.Authority(_intermediate, "Second Intermediate");
        X509Certificate2 stranger = TestPki.Authority(TestPki.Root("Other Root"), "Stranger");

        string? error = Validate([TestPki.Server(second, s_names), stranger, _intermediate, second], "server.test");

        Assert.That(error, Is.Null);
    }

    [Test]
    public void CrossSignedCopyOfTheRoot_LeadsToTheRootItself()
    {
        // The server sends the root signed by an older root nobody trusts any
        // more: the chain stops at the intermediate the trusted root signed.
        ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 root = TestPki.Root("Current Root", rootKey);
        X509Certificate2 crossSigned = TestPki.Authority(TestPki.Root("Retired Root"), "Current Root", key: rootKey);
        X509Certificate2 intermediate = TestPki.Authority(root);

        string? error = CertificateValidator.Validate(
            Bc(TestPki.Server(intermediate, s_names), intermediate, crossSigned), "server.test",
            TrustedRoots.FromCertificates([root.RawData]), DateTime.UtcNow, out _);

        Assert.That(error, Is.Null);
    }

    [Test]
    public void MissingIntermediate_IsNotTrusted()
    {
        string? error = Validate([TestPki.Server(_intermediate, s_names)], "server.test", out short alert);

        Assert.That(error, Does.Contain("may have left out an intermediate"));
        Assert.That(alert, Is.EqualTo(AlertDescription.unknown_ca));
    }

    [Test]
    public void SelfSigned_IsNotTrusted()
    {
        Assert.That(Validate([TestPki.Server(null, s_names)], "server.test"), Is.EqualTo("the certificate is self-signed"));
    }

    [Test]
    public void UntrustedRoot_IsNotTrusted()
    {
        X509Certificate2 otherRoot = TestPki.Root("Other Root");
        X509Certificate2 intermediate = TestPki.Authority(otherRoot);

        string? error = Validate([TestPki.Server(intermediate, s_names), intermediate, otherRoot], "server.test");

        Assert.That(error, Does.Contain("CN=Other Root, which is not a trusted root"));
    }

    [Test]
    public void ForgedSignature_IsNotTrusted()
    {
        // Same names as the real intermediate, another key: its signature cannot verify.
        X509Certificate2 impostor = TestPki.Authority(TestPki.Root(), "Test Intermediate");

        string? error = Validate([TestPki.Server(impostor, s_names), _intermediate], "server.test");

        Assert.That(error, Does.Contain("which is not a trusted root"));
    }

    [Test]
    public void ExpiredServer_IsNotTrusted()
    {
        X509Certificate2 server = TestPki.Server(_intermediate, s_names,
            notBefore: DateTimeOffset.UtcNow.AddDays(-30), notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        string? error = Validate([server, _intermediate], "server.test", out short alert);

        Assert.That(error, Does.StartWith("the certificate expired on"));
        Assert.That(alert, Is.EqualTo(AlertDescription.certificate_expired));
    }

    [Test]
    public void NotYetValidServer_IsNotTrusted()
    {
        X509Certificate2 server = TestPki.Server(_intermediate, s_names,
            notBefore: DateTimeOffset.UtcNow.AddDays(1), notAfter: DateTimeOffset.UtcNow.AddDays(30));

        Assert.That(Validate([server, _intermediate], "server.test"), Does.Contain("is not valid before"));
    }

    [Test]
    public void IssuerThatIsNoAuthority_IsNotTrusted()
    {
        X509Certificate2 notAnAuthority = TestPki.Server(_intermediate, ["middle.test"], usages: [TestPki.ServerAuth]);

        string? error = Validate([TestPki.Server(notAnAuthority, s_names), notAnAuthority, _intermediate], "server.test");

        Assert.That(error, Does.Contain("is not a certificate authority"));
    }

    [Test]
    public void PathLengthConstraint_IsEnforced()
    {
        X509Certificate2 limited = TestPki.Authority(_root, "Limited", pathLength: 0);
        X509Certificate2 below = TestPki.Authority(limited, "Below Limited");

        string? error = Validate([TestPki.Server(below, s_names), below, limited], "server.test");

        Assert.That(error, Does.Contain("allows 0 intermediate certificates under it"));
    }

    [Test]
    public void IssuerWhoseKeyMayNotSignCertificates_IsNotTrusted()
    {
        X509Certificate2 intermediate = TestPki.Authority(_root, "Signer Only", keyUsage: X509KeyUsageFlags.DigitalSignature);

        string? error = Validate([TestPki.Server(intermediate, s_names), intermediate], "server.test");

        Assert.That(error, Does.Contain("may not sign certificates"));
    }

    [Test]
    public void ServerCertificateForClients_IsNotTrusted()
    {
        X509Certificate2 server = TestPki.Server(_intermediate, s_names, usages: [TestPki.ClientAuth]);

        Assert.That(Validate([server, _intermediate], "server.test"), Is.EqualTo("the certificate is not for TLS servers"));
    }

    [Test]
    public void IntermediateRestrictedToClients_IsNotTrusted()
    {
        X509Certificate2 intermediate = TestPki.Authority(_root, "Client CA", usages: [TestPki.ClientAuth]);

        string? error = Validate([TestPki.Server(intermediate, s_names), intermediate], "server.test");

        Assert.That(error, Is.EqualTo("CN=Client CA is not for TLS servers"));
    }

    [Test]
    public void UnknownCriticalExtension_IsNotTrusted()
    {
        X509Certificate2 server = TestPki.Server(_intermediate, s_names, extensions: [TestPki.UnknownCritical()]);

        string? error = Validate([server, _intermediate], "server.test", out short alert);

        Assert.That(error, Does.Contain("critical extension that is not understood"));
        Assert.That(alert, Is.EqualTo(AlertDescription.unsupported_certificate));
    }

    [Test]
    public void NameConstraints_AllowWhatTheyPermit()
    {
        X509Certificate2 constrained = TestPki.Authority(_root, "Constrained", extensions: [TestPki.NameConstraints(["test"], [])]);

        Assert.That(Validate([TestPki.Server(constrained, ["server.test"]), constrained], "server.test"), Is.Null);
    }

    [Test]
    public void NameConstraints_RefuseWhatTheyDoNotPermit()
    {
        X509Certificate2 constrained = TestPki.Authority(_root, "Constrained", extensions: [TestPki.NameConstraints(["test"], [])]);

        string? error = Validate([TestPki.Server(constrained, ["bank.example"]), constrained], "bank.example");

        Assert.That(error, Does.Contain("outside the names its issuer may certify"));
    }

    [Test]
    public void NameConstraints_RefuseWhatTheyExclude()
    {
        X509Certificate2 constrained = TestPki.Authority(_root, "Excluding", extensions: [TestPki.NameConstraints([], ["secret.test"])]);

        string? error = Validate([TestPki.Server(constrained, ["db.secret.test"]), constrained], "db.secret.test");

        Assert.That(error, Does.Contain("outside the names its issuer may certify"));
    }

    [Test]
    public void NameConstraints_ApplyToTheHost_NotOnlyToAWildcard()
    {
        // *.allowed.test is within the permitted names, bad.allowed.test is excluded:
        // the wildcard would cover it.
        X509Certificate2 constrained = TestPki.Authority(_root, "Excluding",
            extensions: [TestPki.NameConstraints(["allowed.test"], ["bad.allowed.test"])]);
        X509Certificate2 server = TestPki.Server(constrained, ["*.allowed.test"]);

        Assert.That(Validate([server, constrained], "good.allowed.test"), Is.Null);
        Assert.That(Validate([server, constrained], "bad.allowed.test"), Does.Contain("outside the names its issuer may certify"));
    }

    [Test]
    public void Sha1Signature_IsNotTrusted()
    {
        // The desktop signs SHA-1 with RSA only, so the issuer has an RSA key.
        X509Certificate2 rsaIntermediate = TestPki.Authority(_root, "RSA Intermediate", key: RSA.Create(2048));
        X509Certificate2 server = TestPki.Server(rsaIntermediate, s_names, hash: HashAlgorithmName.SHA1);

        string? error = Validate([server, rsaIntermediate], "server.test");

        Assert.That(error, Does.StartWith("the certificate is signed with SHA-1withRSA"));
        Assert.That(error, Does.EndWith("which is too weak to trust"));
    }

    [Test]
    public void Sha1SignedIntermediate_IsNotTrusted()
    {
        X509Certificate2 root = TestPki.Root("RSA Root", RSA.Create(2048));
        X509Certificate2 intermediate = TestPki.Authority(root, "Old Intermediate", hash: HashAlgorithmName.SHA1);

        string? error = CertificateValidator.Validate(Bc(TestPki.Server(intermediate, s_names), intermediate), "server.test",
            TrustedRoots.FromCertificates([root.RawData]), DateTime.UtcNow, out _);

        Assert.That(error, Does.StartWith("CN=Old Intermediate is signed with SHA-1withRSA"));
    }

    [Test]
    public void ShortRsaKey_IsNotTrusted()
    {
        X509Certificate2 server = TestPki.Server(_intermediate, s_names, key: RSA.Create(1024));

        Assert.That(Validate([server, _intermediate], "server.test"), Does.Contain("1024-bit RSA key"));
    }

    [Test]
    public void RsaChain_IsTrusted()
    {
        X509Certificate2 root = TestPki.Root("RSA Root", RSA.Create(2048));
        X509Certificate2 intermediate = TestPki.Authority(root, "RSA Intermediate", key: RSA.Create(2048));
        X509Certificate2 server = TestPki.Server(intermediate, s_names, key: RSA.Create(2048));

        string? error = CertificateValidator.Validate(Bc(server, intermediate), "server.test",
            TrustedRoots.FromCertificates([root.RawData]), DateTime.UtcNow, out _);

        Assert.That(error, Is.Null);
    }

    [Test]
    public void Dates_AreCheckedLast()
    {
        // Expired and for another host: the host is what is reported, so a
        // date error always means nothing else is wrong.
        X509Certificate2 server = TestPki.Server(_intermediate, ["elsewhere.test"],
            notBefore: DateTimeOffset.UtcNow.AddDays(-30), notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        Assert.That(Validate([server, _intermediate], "server.test"), Does.Contain("not server.test"));
    }

    [Test]
    public void ExpiredRoot_GivesWayToAValidOneOfTheSameName()
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 expired = TestPki.Root("Renewed Root", key,
            notBefore: DateTimeOffset.UtcNow.AddDays(-400), notAfter: DateTimeOffset.UtcNow.AddDays(-10));
        X509Certificate2 renewed = TestPki.Root("Renewed Root", key);
        X509Certificate2 intermediate = TestPki.Authority(renewed);
        TrustedRoots roots = TrustedRoots.FromCertificates([expired.RawData, renewed.RawData]);

        Assert.That(CertificateValidator.Validate(Bc(TestPki.Server(intermediate, s_names), intermediate), "server.test",
            roots, DateTime.UtcNow, out _), Is.Null);
    }

    [Test]
    public void ExpiredRoot_IsReportedWhenNothingElseLeadsToARoot()
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 expired = TestPki.Root("Old Root", key,
            notBefore: DateTimeOffset.UtcNow.AddDays(-400), notAfter: DateTimeOffset.UtcNow.AddDays(-10));
        X509Certificate2 intermediate = TestPki.Authority(TestPki.Root("Old Root", key));

        string? error = CertificateValidator.Validate(Bc(TestPki.Server(intermediate, s_names), intermediate), "server.test",
            TrustedRoots.FromCertificates([expired.RawData]), DateTime.UtcNow, out short alert);

        Assert.That(error, Does.StartWith("the root CN=Old Root expired on"));
        Assert.That(alert, Is.EqualTo(AlertDescription.certificate_expired));
    }

    [TestCase("server.test", "server.test")]
    [TestCase("SERVER.test", "server.test")]
    [TestCase("127.0.0.1", "127.0.0.1")]
    public void Host_IsFoundInTheAlternativeNames(string host, string name)
    {
        Assert.That(Validate([TestPki.Server(_intermediate, [name]), _intermediate], host), Is.Null);
    }

    [Test]
    public void OtherHost_IsNotTrusted()
    {
        string? error = Validate([TestPki.Server(_intermediate, ["a.test", "b.test", "10.0.0.1"]), _intermediate], "c.test");

        Assert.That(error, Is.EqualTo("the certificate is for a.test, b.test, 10.0.0.1, not c.test"));
    }

    [Test]
    public void AddressNamedOnlyAsADnsName_IsNotTrusted()
    {
        Assert.That(Validate([TestPki.Server(_intermediate, ["server.test"]), _intermediate], "10.0.0.1"), Does.Contain("not 10.0.0.1"));
    }

    [Test]
    public void CertificateWithoutAlternativeNames_IsNotTrusted()
    {
        // The common name is not looked at, as in browsers.
        X509Certificate2 server = TestPki.Server(_intermediate, []);

        Assert.That(Validate([server, _intermediate], "no name"), Does.Contain("has no subject alternative names"));
    }

    [TestCase("*.example.com", "www.example.com", true)]
    [TestCase("*.example.com", "WWW.Example.COM", true)]
    [TestCase("*.example.com", "example.com", false)]
    [TestCase("*.example.com", "a.b.example.com", false)]
    [TestCase("*.example.com", ".example.com", false)]
    [TestCase("*.com", "example.com", false)]
    [TestCase("*", "example", false)]
    [TestCase("w*.example.com", "www.example.com", false)]
    [TestCase("*.*.example.com", "a.b.example.com", false)]
    [TestCase("example.com.", "example.com", true)]
    [TestCase("example.com", "example.com.", true)]
    [TestCase("example.com", "example.org", false)]
    public void DnsNames_MatchAsRfc6125Says(string pattern, string host, bool matches)
    {
        Assert.That(CertificateValidator.MatchesDnsName(pattern, host), Is.EqualTo(matches));
    }

    [Test]
    public void EmptyChain_IsNotTrusted()
    {
        Assert.That(Validate([], "server.test"), Is.EqualTo("the server sent no certificate"));
    }

    [Test]
    public void MozillaRoots_AreEmbedded()
    {
        TrustedRoots roots = TrustedRoots.Mozilla;

        Assert.That(roots.Count, Is.GreaterThan(100));
        Org.BouncyCastle.Asn1.X509.X509Name isrg = new("C=US,O=Internet Security Research Group,CN=ISRG Root X1");
        Assert.That(roots.FindBySubject(isrg).Count(), Is.EqualTo(1));
    }

    private string? Validate(X509Certificate2[] chain, string host) => Validate(chain, host, out _);

    private string? Validate(X509Certificate2[] chain, string host, out short alert) =>
        CertificateValidator.Validate(Bc(chain), host, _roots, DateTime.UtcNow, out alert);

    private static Org.BouncyCastle.X509.X509Certificate[] Bc(params X509Certificate2[] chain) =>
        chain.Select(TestPki.ToBouncyCastle).ToArray();
}
