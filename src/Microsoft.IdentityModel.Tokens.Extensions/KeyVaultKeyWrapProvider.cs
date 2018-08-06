﻿//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

namespace Microsoft.IdentityModel.Tokens.Extensions
{
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault;
    using Microsoft.IdentityModel.Logging;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Provides wrap and unwrap operations using Azure Key Vault.
    /// </summary>
    public class KeyVaultKeyWrapProvider : KeyWrapProvider
    {
        private readonly IKeyVaultClient _client;
        private readonly KeyVaultSecurityKey _key;
        private readonly string _algorithm;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureProvider"/> class.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        public KeyVaultKeyWrapProvider(SecurityKey key, string algorithm)
        {
            _algorithm = string.IsNullOrEmpty(algorithm) ? throw LogHelper.LogArgumentNullException(nameof(algorithm)) : algorithm;
            _key = key as KeyVaultSecurityKey ?? throw LogHelper.LogArgumentNullException(nameof(key));
            _client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(_key.Callback));
        }

        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        public override string Algorithm => _algorithm;

        /// <summary>
        /// Gets or sets a user context for a <see cref="KeyWrapProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This can be used by runtimes or for extensibility scenarios.</remarks>
        public override string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public override SecurityKey Key => _key;

        /// <summary>
        /// Unwrap a key.
        /// </summary>
        /// <param name="keyBytes">key to unwrap.</param>
        /// <returns>Unwrapped key.</returns>
        public override byte[] UnwrapKey(byte[] keyBytes)
        {
            return UnwrapKeyAsync(keyBytes, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Wrap a key.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>wrapped key.</returns>
        public override byte[] WrapKey(byte[] keyBytes)
        {
            return WrapKeyAsync(keyBytes, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _disposed = true;
                    _client.Dispose();
                }
            }
        }

        /// <summary>
        /// Unwraps a symmetric key using Azure Key Vault.
        /// </summary>
        /// <param name="keyBytes">key to unwrap.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns>Unwrapped key.</returns>
        private async Task<byte[]> UnwrapKeyAsync(byte[] keyBytes, CancellationToken cancellation)
        {
            return (await _client.UnwrapKeyAsync(_key.KeyId, Algorithm, keyBytes, cancellation)).Result;
        }

        /// <summary>
        /// Wraps a symmetric key using Azure Key Vault.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns>wrapped key.</returns>
        private async Task<byte[]> WrapKeyAsync(byte[] keyBytes, CancellationToken cancellation)
        {
            return (await _client.WrapKeyAsync(_key.KeyId, Algorithm, keyBytes, cancellation)).Result;
        }
    }
}
