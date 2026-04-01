FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Install OpenSSL 3.5 from source (ML-DSA requires 3.5+)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential wget ca-certificates perl \
    && wget -q https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz \
    && tar -xzf openssl-3.5.0.tar.gz \
    && cd openssl-3.5.0 \
    && ./Configure --prefix=/usr/local/openssl3.5 --openssldir=/usr/local/openssl3.5/ssl \
    && make -j$(nproc) \
    && make install_sw \
    && cd .. && rm -rf openssl-3.5.0 openssl-3.5.0.tar.gz \
    && apt-get purge -y build-essential wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENV LD_LIBRARY_PATH=/usr/local/openssl3.5/lib64:$LD_LIBRARY_PATH
ENV OPENSSL_CONF=/usr/local/openssl3.5/ssl/openssl.cnf

WORKDIR /app

# Copy solution and restore
COPY QuantumJwt.sln ./
COPY src/QuantumJwt/QuantumJwt.csproj src/QuantumJwt/
COPY examples/QuantumJwt.Demo/QuantumJwt.Demo.csproj examples/QuantumJwt.Demo/
COPY tests/QuantumJwt.Tests/QuantumJwt.Tests.csproj tests/QuantumJwt.Tests/
RUN dotnet restore examples/QuantumJwt.Demo/QuantumJwt.Demo.csproj

# Copy source and build
COPY src/ src/
COPY examples/ examples/
RUN dotnet publish examples/QuantumJwt.Demo/QuantumJwt.Demo.csproj -c Release -o /app/publish

# Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0

# Copy OpenSSL 3.5 from build stage
COPY --from=build /usr/local/openssl3.5 /usr/local/openssl3.5
ENV LD_LIBRARY_PATH=/usr/local/openssl3.5/lib64:$LD_LIBRARY_PATH
ENV OPENSSL_CONF=/usr/local/openssl3.5/ssl/openssl.cnf

WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:5000
EXPOSE 5000

ENTRYPOINT ["dotnet", "QuantumJwt.Demo.dll"]
