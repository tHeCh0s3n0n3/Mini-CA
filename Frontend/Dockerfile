# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Frontend/Frontend.csproj", "Frontend/"]
COPY ["Common/Common.csproj", "Common/"]
COPY ["DAL/DAL.csproj", "DAL/"]
RUN dotnet restore "Frontend/Frontend.csproj"
COPY . .
WORKDIR "/src/Frontend"
RUN dotnet publish "Frontend.csproj" -c Release -o /app/publish

# Runtime Stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
# Tag the image with the source repo
LABEL org.opencontainers.image.source="https://github.com/tHeCh0s3n0n3/Mini-CA"
WORKDIR /app
COPY --from=build /app/publish .
# Environment variables for ASP.NET Core
ENV ASPNETCORE_URLS=http://+:80
EXPOSE 80
ENTRYPOINT ["dotnet", "Frontend.dll"]
