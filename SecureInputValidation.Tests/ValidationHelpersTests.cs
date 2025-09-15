using NUnit.Framework;
using SecureInputValidation.Helpers;
using NUnit.Framework.Legacy;

namespace SecureInputValidation.Tests
{
    public class ValidationHelpersTests
    {
        [TestCase("Hello123@", true)]
        [TestCase("Bad!Input", false)]
        [TestCase("", false)]
        [TestCase("OnlyLetters", true)]
        [TestCase("123456", true)]
        [TestCase("With#Hash", true)]
        [TestCase("With$Dollar", true)]
        public void IsValidInput_ReturnsExpectedResult(string input, bool expected)
        {
            var result = ValidationHelpers.IsValidInput(input);
            Assert.That(result, Is.EqualTo(expected));
        }

    }
}
