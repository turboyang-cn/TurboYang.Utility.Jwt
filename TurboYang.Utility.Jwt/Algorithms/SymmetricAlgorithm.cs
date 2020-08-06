using System;
using System.Text;

namespace TurboYang.Utility.Jwt.Algorithms
{
    public abstract class SymmetricAlgorithm : Algorithm
    {
        internal SymmetricAlgorithm()
        {
        }

        public SymmetricAlgorithm(String key)
            : this(Encoding.UTF8.GetBytes(key))
        {
        }

        public SymmetricAlgorithm(Byte[] key)
        {
            Key = key;
        }

        internal protected Byte[] Key { get; internal set; }
    }
}
