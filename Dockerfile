FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY SentinelFlow.sln ./
COPY src/SentinelFlow.Api/SentinelFlow.Api.csproj src/SentinelFlow.Api/
RUN dotnet restore src/SentinelFlow.Api/SentinelFlow.Api.csproj
COPY src/SentinelFlow.Api src/SentinelFlow.Api
RUN dotnet publish src/SentinelFlow.Api/SentinelFlow.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
WORKDIR /app
RUN apk upgrade --no-cache \
    && addgroup -S sentinel \
    && adduser -S -G sentinel sentinel
COPY --from=build --chown=sentinel:sentinel /app/publish .
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:4000
USER sentinel
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4000/api/health || exit 1
ENTRYPOINT ["dotnet", "SentinelFlow.Api.dll"]
