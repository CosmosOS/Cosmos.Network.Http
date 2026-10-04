// nanoFramework.TestFramework, as nanoFramework's tests use it, over MSTest: its attributes are MSTest's (aliased in
// GlobalUsings.cs), and its Assert and OutputHelper forward to MSTest's.

using System;
using MSTestAssert = Microsoft.VisualStudio.TestTools.UnitTesting.Assert;

namespace nanoFramework.TestFramework
{
    /// <summary>
    /// nanoFramework.TestFramework's Assert: MSTest's, with the xUnit-style names it also has.
    /// </summary>
    public static class Assert
    {
        public static void AreEqual<T>(T expected, T actual, string message = "") => MSTestAssert.AreEqual(expected, actual, message);

        public static void AreNotEqual<T>(T notExpected, T actual, string message = "") => MSTestAssert.AreNotEqual(notExpected, actual, message);

        public static void Equal<T>(T expected, T actual, string message = "") => MSTestAssert.AreEqual(expected, actual, message);

        public static void IsTrue(bool condition, string message = "") => MSTestAssert.IsTrue(condition, message);

        public static void IsFalse(bool condition, string message = "") => MSTestAssert.IsFalse(condition, message);

        public static void IsNull(object value, string message = "") => MSTestAssert.IsNull(value, message);

        public static void Null(object value, string message = "") => MSTestAssert.IsNull(value, message);

        public static void IsNotNull(object value, string message = "") => MSTestAssert.IsNotNull(value, message);

        public static void NotNull(object value, string message = "") => MSTestAssert.IsNotNull(value, message);

        public static void AreSame(object expected, object actual, string message = "") => MSTestAssert.AreSame(expected, actual, message);

        public static void Same(object expected, object actual, string message = "") => MSTestAssert.AreSame(expected, actual, message);

        public static void AreNotSame(object notExpected, object actual, string message = "") => MSTestAssert.AreNotSame(notExpected, actual, message);

        /// <summary>
        /// Passes if <paramref name="action"/> throws <paramref name="exceptionType"/> exactly, as nanoFramework's does.
        /// </summary>
        public static void ThrowsException(Type exceptionType, Action action, string message = "")
        {
            try
            {
                action();
            }
            catch (Exception e)
            {
                if (e.GetType() != exceptionType)
                {
                    MSTestAssert.Fail($"Expected {exceptionType.Name}, got {e.GetType().Name}: {e.Message}. {message}");
                }

                return;
            }

            MSTestAssert.Fail($"Expected {exceptionType.Name}, nothing was thrown. {message}");
        }

        public static void Throws(Type exceptionType, Action action, string message = "") => ThrowsException(exceptionType, action, message);

        public static void SkipTest(string message = "") => MSTestAssert.Inconclusive(message);
    }

    /// <summary>
    /// nanoFramework.TestFramework's CollectionAssert: MSTest's.
    /// </summary>
    public static class CollectionAssert
    {
        public static void AreEqual(System.Collections.ICollection expected, System.Collections.ICollection actual, string message = "") => Microsoft.VisualStudio.TestTools.UnitTesting.CollectionAssert.AreEqual(expected, actual, message);
    }

    /// <summary>
    /// nanoFramework.TestFramework's OutputHelper: the test's output.
    /// </summary>
    public static class OutputHelper
    {
        public static void WriteLine(string message) => Console.WriteLine(message);

        public static void Write(string message) => Console.Write(message);
    }
}
