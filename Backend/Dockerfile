# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Backend/Backend.csproj", "Backend/"]
COPY ["Common/Common.csproj", "Common/"]
COPY ["DAL/DAL.csproj", "DAL/"]
RUN dotnet restore "Backend/Backend.csproj"
COPY . .
WORKDIR "/src/Backend"
RUN dotnet publish "Backend.csproj" -c Release -o /app/publish


# Runtime Stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
# Tag the image with the source repo
LABEL org.opencontainers.image.source="https://github.com/tHeCh0s3n0n3/Mini-CA"
# Install curl for healthchecks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/publish .
# Environment variables for ASP.NET Core
ENV ASPNETCORE_URLS=http://+:80
EXPOSE 80
ENTRYPOINT ["dotnet", "Backend.dll"]
