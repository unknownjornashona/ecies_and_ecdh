cmake_minimum_required(VERSION 3.10)

# 项目名称
project(EncryptionApp)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 源文件
set(SOURCES
    main.cpp
    EncryptionManager.cpp
)

# 生成可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 链接 OpenSSL 库
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)

# 安装目标
install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin)

# 安装其他项目文件
install(FILES
    COPYRIGHT.md
    README.md
    LICENSE.md
    CHANGELOG.md
    INSTALL.md
    CONTRIBUTING.md
    CODE_OF_CONDUCT.md
    docs/Doxyfile
    DESTINATION doc
)

# 设置 CMake 输出目录
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/install)

# 添加 Doxygen 支持
find_package(Doxygen)

if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_SOURCE_DIR}/docs/Doxyfile)
    set(DOXYGEN_OUT ${CMAKE_BINARY_DIR}/docs)

    # 添加自定义目标以生成文档
    add_custom_target(doc ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_IN} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
else()
    message(WARNING "Doxygen not found. Documentation will not be generated.")
endif()

# 添加 CPack 支持以生成发布包
include(CPack)

set(CPACK_GENERATOR "ZIP")  # 可以选择其他生成器，如 "TGZ", "DEB", "RPM" 等
set(CPACK_PACKAGE_NAME "EncryptionApp")
set(CPACK_VERSION_MAJOR "1")
set(CPACK_VERSION_MINOR "0")
set(CPACK_VERSION_PATCH "0")
set(CPACK_PACKAGE_CONTACT "your_email@example.com")  # 替换为您的联系信息
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A simple encryption application.")
set(CPACK_PACKAGE_VENDOR "YourCompany")  # 替换为您的公司名称

# 在执行 cpack 时包括生成的可执行文件和文档
install(FILES ${CMAKE_INSTALL_PREFIX}/bin/${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY ${CMAKE_INSTALL_PREFIX}/doc/ DESTINATION doc)

# 添加测试支持（可选）
enable_testing()
# Add any test executables and libraries here
