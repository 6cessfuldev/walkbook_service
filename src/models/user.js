const { Model, DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  class User extends Model {
    static associate(models) {
      // 여기에 다른 모델과의 관계 정의
    }
  }
  
  User.init({
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      comment: '사용자 고유 ID'
    },
    uid: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      comment: '고유한 식별자 (외부 API 연동 시 활용 가능)'
    },
    email: {
      type: DataTypes.TEXT,
      unique: true,
      comment: '이메일 (소셜 로그인 시 필수 아님)'
    },
    username: {
      type: DataTypes.TEXT,
      unique: true,
      allowNull: false,
      comment: '닉네임 또는 사용자명 (필수)'
    },
    password_hash: {
      type: DataTypes.TEXT,
      comment: '비밀번호 (소셜 로그인 시 NULL)'
    },
    provider: {
      type: DataTypes.TEXT,
      allowNull: false,
      comment: '로그인 제공자 (\'google\', \'apple\', \'kakao\', etc.)'
    },
    provider_id: {
      type: DataTypes.TEXT,
      unique: true,
      comment: '소셜 로그인 사용자의 고유 ID'
    },
    profile_image_url: {
      type: DataTypes.TEXT,
      comment: '프로필 이미지 URL'
    },
    created_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
      comment: '생성일시'
    },
    updated_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
      comment: '업데이트일시'
    },
    deleted_at: {
      type: DataTypes.DATE,
      comment: '계정 삭제(비활성화) 처리'
    }
  }, {
    sequelize,
    modelName: 'User',
    tableName: 'users',
    timestamps: true,
    underscored: true,
    paranoid: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: 'deleted_at',
    indexes: [
      {
        unique: true,
        fields: ['provider', 'provider_id'],
        name: 'unique_provider_id'
      }
    ]
  });
  
  return User;
};