import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSetRecoilState, useResetRecoilState } from 'recoil';
import styled from 'styled-components';
import { AiOutlineSearch } from 'react-icons/ai';
import { SlHome } from 'react-icons/sl';

import {
  navSearchValue,
  categoryFocus,
  mainDataState,
  settingUrl,
  pageState,
  NextPage,
} from '../../atoms';
import { NavLeftButtonContainer, NavRightButtonContainer } from './NavButton';

function Nav({ navColor, buttonColor }) {
  const [currentSearch, setCurrentSearch] = useState('');

  const setSearch = useSetRecoilState(navSearchValue);
  const setFocusCategoryID = useSetRecoilState(categoryFocus);
  const setPage = useSetRecoilState(pageState);
  const resetMainPlaceData = useResetRecoilState(mainDataState);
  const setUrl = useSetRecoilState(settingUrl);
  const setHasNextPage = useSetRecoilState(NextPage);

  const navigate = useNavigate();

  const invalidate = () => {
    setCurrentSearch('');
    resetMainPlaceData();
    setHasNextPage(true);
    setPage(() => 1);
    setFocusCategoryID(0);
    navigate('/');
  };

  const onChangeSearch = event => {
    setCurrentSearch(event.target.value);
  };

  // eslint-disable-next-line consistent-return
  const onSubmit = event => {
    event.preventDefault();

    const trimmedSearch = currentSearch.trim();
    const replacedSearch = trimmedSearch.replace(/ +(?= )/g, '');

    setSearch(replacedSearch);

    if (!trimmedSearch) {
      alert('검색어를 입력해주세요');
      return setCurrentSearch('');
    }

    const encoded = encodeURI(replacedSearch);

    const url = `/search/${encoded}?size=20&page=`;

    setUrl(() => url);
    invalidate();
  };

  // eslint-disable-next-line consistent-return
  const onClickSearch = async () => {
    const trimmedSearch = currentSearch.trim();
    const replacedSearch = trimmedSearch.replace(/ +(?= )/g, '');

    setSearch(replacedSearch);

    if (!trimmedSearch) {
      alert('검색어를 입력해주세요');
      return setCurrentSearch('');
    }

    const encoded = encodeURI(replacedSearch);

    const url = `/search/${encoded}?size=20&page=`;

    setUrl(() => url);
    invalidate();
  };

  const onClickHomeIcon = () => {
    setSearch('');
    invalidate();
    setUrl(() => `/home?size=20&page=`);
  };

  return (
    <NavContainer>
      <NavBackground navColor={navColor}>
        <SlHome onClick={onClickHomeIcon} className="NavLogo" />
        {/* <div className="structure" /> */}
        <SearchContainer onSubmit={onSubmit}>
          <SearchInput value={currentSearch} onChange={onChangeSearch} />
          <AiOutlineSearch onClick={onClickSearch} className="searchIcon" />
        </SearchContainer>
        <ButtonContainer>
          <NavLeftButtonContainer buttonColor={buttonColor} />
          <NavRightButtonContainer />
        </ButtonContainer>
      </NavBackground>
    </NavContainer>
  );
}

export default Nav;

const NavContainer = styled.div`
  position: relative;
  z-index: 100;
`;

const NavBackground = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  width: 100vw;
  height: 70px;
  background-color: ${props => props.navColor || '#89bbff'};
  box-shadow: rgba(0, 0, 0, 0.35) 0px 5px 15px;
  /* 
  .structure {
    width: 116px;
  } */

  .NavLogo {
    font-size: 2rem;
    margin-right: 9vw;
    margin-left: 20px;
    margin-top: 10px;
    margin-bottom: 10px;
    color: #2b2b2b;
    &:hover {
      cursor: pointer;
    }
  }
`;

const SearchContainer = styled.form`
  width: 40%;
  display: flex;
  justify-content: row;
  position: relative;
  margin: 0;
  text-align: center;
  align-items: center;
  .searchIcon {
    position: absolute;
    right: 0;
    margin: 0;
    font-size: 1.4rem;
    color: #515151;
    margin-right: 20px;
    padding-top: 10px;
    padding-bottom: 10px;
    &:hover {
      font-size: 1.8rem;
      color: #89bbff;
      cursor: pointer;
    }
  }
`;

const SearchInput = styled.input`
  font-family: inherit;
  margin: 10px 0;
  padding: 10px 45px 10px 25px;
  width: 100%;
  border-radius: 20px;
  border: none;
  background-color: #fff9eb;
  box-shadow: rgba(0, 0, 0, 0.35) 0px 5px 15px;
  caret-color: #89bbff;
  &:focus {
    outline: none;
  }
`;

const ButtonContainer = styled.div`
  display: flex;
  justify-content: right;
  align-items: center;
  margin-right: 20px;
  margin-left: 20px;
  /* border: 1px solid red; */
  width: 188px;
`;